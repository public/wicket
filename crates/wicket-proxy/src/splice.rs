//! Splice-through for hosts a zone allows wholesale (#62; which hosts: [`wicket_core::splice`]).
//!
//! The CONNECT is decided on its hostname. wicket dials the upstream itself, at addresses it has
//! checked (#116), before it answers the CONNECT, so a refused dial is the CONNECT's answer. Then
//! it reads the box's TLS ClientHello: only if it names the CONNECT host in SNI (and doesn't use
//! Encrypted ClientHello, which could name another site behind the same front) are the bytes
//! relayed unmodified, with splice(2) where both ends are sockets and a copy loop otherwise. Anything
//! else (no SNI, another name, not TLS) falls back to full interception with the bytes already read,
//! exactly as if the host weren't spliced: when in doubt, intercept.
//!
//! One audit row per connection, written when it closes (or is cut), with the bytes each way.

use crate::egress::{Egress, Upstream};
use crate::{Event, RunCtx};
use bytes::{Buf, Bytes};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

/// How long the box has to send its ClientHello after the CONNECT is answered.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest ClientHello wicket reads (a TLS record is at most 16 KiB; post-quantum key shares
/// make hellos a few KiB, and a hello may span records).
const MAX_HELLO: usize = 64 * 1024;
/// How often a spliced connection checks that its activation is still current (#70).
const FENCE_CHECK: Duration = Duration::from_secs(2);
/// Pipe (splice) or buffer (copy) size per direction.
const CHUNK: usize = 256 * 1024;

/// What the box's ClientHello says, as far as splicing cares.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Hello {
    /// The one `host_name` in the server_name extension, lowercased; None if absent or ambiguous.
    pub sni: Option<String>,
    /// Encrypted ClientHello (the outer SNI is then only the front's name).
    pub ech: bool,
}

/// Parses a ClientHello handshake message (type, length, body). None if it isn't one, or is cut.
pub(crate) fn parse_hello(msg: &[u8]) -> Option<Hello> {
    let mut b = msg;
    if b.first() != Some(&1) || b.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([0, b[1], b[2], b[3]]) as usize;
    b = b.get(4..4 + len)?;
    let take = |b: &mut &[u8], n: usize| -> Option<Vec<u8>> {
        let (x, rest) = (b.get(..n)?, b.get(n..)?);
        let x = x.to_vec();
        *b = rest;
        Some(x)
    };
    let u16_at = |b: &mut &[u8]| -> Option<usize> {
        let x = take(b, 2)?;
        Some(u16::from_be_bytes([x[0], x[1]]) as usize)
    };
    take(&mut b, 2 + 32)?; // version, random
    let sid = *take(&mut b, 1)?.first()? as usize;
    take(&mut b, sid)?;
    let cs = u16_at(&mut b)?;
    take(&mut b, cs)?;
    let comp = *take(&mut b, 1)?.first()? as usize;
    take(&mut b, comp)?;
    let mut hello = Hello::default();
    if b.is_empty() {
        return Some(hello);
    }
    let ext_len = u16_at(&mut b)?;
    let mut exts = b.get(..ext_len)?;
    let mut sni_seen = false;
    while !exts.is_empty() {
        let ty = u16_at(&mut exts)?;
        let n = u16_at(&mut exts)?;
        let mut data: &[u8] = &take(&mut exts, n)?;
        match ty {
            0 => {
                if sni_seen {
                    hello.sni = None;
                    return Some(hello);
                }
                sni_seen = true;
                let list = u16_at(&mut data)?;
                let mut names = data.get(..list)?;
                let mut found = Vec::new();
                while !names.is_empty() {
                    let kind = *take(&mut names, 1)?.first()?;
                    let l = u16_at(&mut names)?;
                    let name = take(&mut names, l)?;
                    if kind == 0 {
                        found.push(name);
                    }
                }
                // Exactly one host name, in ASCII; anything else is ambiguous.
                hello.sni = match found.as_slice() {
                    [one] if one.is_ascii() => Some(String::from_utf8_lossy(one).trim_end_matches('.').to_ascii_lowercase()),
                    _ => None,
                };
            }
            0xfe0d => hello.ech = true,
            _ => {}
        }
    }
    Some(hello)
}

/// Reads TLS records from `s` until the first handshake message (the ClientHello) is complete.
/// Returns every byte read, and the parsed hello (None if the bytes aren't a ClientHello).
async fn read_hello<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<(Vec<u8>, Option<Hello>)> {
    let mut raw = Vec::new();
    let mut msg = Vec::new();
    loop {
        // One record header, then its body.
        let start = raw.len();
        raw.resize(start + 5, 0);
        if s.read_exact(&mut raw[start..]).await.is_err() {
            raw.truncate(start);
            return Ok((raw, None));
        }
        let h = &raw[start..start + 5];
        if h[0] != 22 || h[1] != 3 {
            return Ok((raw, None));
        }
        let n = u16::from_be_bytes([h[3], h[4]]) as usize;
        if n == 0 || raw.len() + n > MAX_HELLO {
            return Ok((raw, None));
        }
        let body = raw.len();
        raw.resize(body + n, 0);
        s.read_exact(&mut raw[body..]).await?;
        msg.extend_from_slice(&raw[body..]);
        if msg.len() >= 4 {
            let want = 4 + u32::from_be_bytes([0, msg[1], msg[2], msg[3]]) as usize;
            if want > MAX_HELLO {
                return Ok((raw, None));
            }
            if msg.len() >= want {
                return Ok((raw, parse_hello(&msg[..want])));
            }
        }
    }
}

/// A stream with bytes already read from it put back in front.
pub(crate) struct Prefixed<S> {
    pre: Bytes,
    inner: S,
}

impl<S> Prefixed<S> {
    pub(crate) fn new(pre: Bytes, inner: S) -> Self {
        Prefixed { pre, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if !self.pre.is_empty() {
            let n = self.pre.len().min(buf.remaining());
            buf.put_slice(&self.pre[..n]);
            self.pre.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Dials `host`:443 at checked addresses: an address pinned in `upstream.resolve` (the operator's
/// choice), else what DNS answers if every address is public (#116).
pub(crate) async fn dial(upstream: &Upstream, host: &str) -> io::Result<TcpStream> {
    let addrs: Vec<SocketAddr> = match upstream.resolve.get(host) {
        Some(a) => vec![*a],
        None => crate::dial::resolve_public(&upstream.lookup(), host, 443).await?,
    };
    let mut last = io::Error::new(io::ErrorKind::NotFound, format!("{host}: no address"));
    for a in addrs {
        match tokio::time::timeout(Duration::from_secs(15), TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => last = e,
            Err(_) => last = io::Error::new(io::ErrorKind::TimedOut, format!("{host}: connect timed out")),
        }
    }
    Err(last)
}

/// The audit row for one spliced connection, written when it is dropped (closed, failed or cut).
struct Record {
    ctx: RunCtx,
    host: String,
    rule: usize,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    started: Instant,
    /// Set when the connection ended for a reason worth saying (superseded, an error).
    end: std::sync::Mutex<Option<String>>,
    /// The connection fell back to interception: no row here (its requests have their own).
    skip: std::sync::atomic::AtomicBool,
}

impl Drop for Record {
    fn drop(&mut self) {
        if self.skip.load(Ordering::Relaxed) {
            return;
        }
        let end = self.end.lock().ok().and_then(|e| e.clone()).map(|e| format!("; {e}")).unwrap_or_default();
        self.ctx.emit(Event::Egress {
            method: "CONNECT".into(),
            host: self.host.clone(),
            path: "/".into(),
            risk: "-".into(),
            outcome: "spliced".into(),
            detail: format!(
                "reach rule {} allows the host wholesale: not inspected; {} bytes up, {} down, {:.1}s{end}",
                self.rule,
                self.up.load(Ordering::Relaxed),
                self.down.load(Ordering::Relaxed),
                self.started.elapsed().as_secs_f64()
            ),
        });
    }
}

/// Serves one spliced CONNECT after its 200: checks the ClientHello, then relays (or falls back to
/// interception).
pub(crate) async fn serve(egress: Arc<Egress>, upgraded: hyper::upgrade::Upgraded, upstream: TcpStream, host: String, rule: usize) {
    let rec = Arc::new(Record {
        ctx: egress.ctx.clone(),
        host: host.clone(),
        rule,
        up: Default::default(),
        down: Default::default(),
        started: Instant::now(),
        end: Default::default(),
        skip: Default::default(),
    });
    // The box's raw socket, for splice(2), with whatever hyper had already read from it.
    let (pre, side) = match upgraded.downcast::<hyper_util::rt::TokioIo<tokio::net::UnixStream>>() {
        Ok(parts) => (parts.read_buf, Side::Unix(parts.io.into_inner())),
        Err(up) => (Bytes::new(), Side::Other(Box::new(hyper_util::rt::TokioIo::new(up)))),
    };
    let mut boxside = Prefixed::new(pre, side);
    let (raw, hello) = match tokio::time::timeout(HELLO_TIMEOUT, read_hello(&mut boxside)).await {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => {
            *rec.end.lock().unwrap() = Some(format!("no ClientHello: {e}"));
            return;
        }
        Err(_) => {
            *rec.end.lock().unwrap() = Some("no ClientHello in time".into());
            return;
        }
    };
    let mut pre = boxside.pre.to_vec();
    let side = boxside.inner;
    let ok = matches!(&hello, Some(h) if h.sni.as_deref() == Some(host.as_str()) && !h.ech);
    let mut all = raw;
    all.append(&mut pre);
    if !ok {
        // Not a plain ClientHello for this host: intercept, as for any other host.
        rec.skip.store(true, Ordering::Relaxed);
        drop(upstream);
        tracing::debug!(%host, ?hello, "ClientHello doesn't qualify for splicing; intercepting");
        let io = Prefixed::new(Bytes::from(all), side);
        if let Err(e) = egress.clone().tunnel_io(io, host.clone()).await {
            tracing::debug!(%host, error = %e, "tunnel ended");
        }
        return;
    }
    let relay = relay(side, upstream, Bytes::from(all), rec.up.clone(), rec.down.clone());
    let ctx = egress.ctx.clone();
    let fenced = async move {
        if ctx.fence.is_none() {
            return std::future::pending::<String>().await;
        }
        loop {
            tokio::time::sleep(FENCE_CHECK).await;
            if let Some(why) = ctx.superseded() {
                return why;
            }
        }
    };
    tokio::select! {
        r = relay => if let Err(e) = r { *rec.end.lock().unwrap() = Some(format!("ended: {e}")); },
        why = fenced => *rec.end.lock().unwrap() = Some(format!("cut: {why}")),
    }
}

/// The box's end of a spliced connection.
pub(crate) enum Side {
    /// The box's unix socket itself (splice(2) works on it).
    Unix(tokio::net::UnixStream),
    /// Anything else hyper handed over (a copy loop).
    Other(Box<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>>),
}

impl AsyncRead for Side {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Side::Unix(s) => Pin::new(s).poll_read(cx, buf),
            Side::Other(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Side {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Side::Unix(s) => Pin::new(s).poll_write(cx, buf),
            Side::Other(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Side::Unix(s) => Pin::new(s).poll_flush(cx),
            Side::Other(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Side::Unix(s) => Pin::new(s).poll_shutdown(cx),
            Side::Other(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Relays both ways until both are done: `first` (the ClientHello and anything after it) goes
/// upstream before anything else.
async fn relay(side: Side, mut up: TcpStream, first: Bytes, up_n: Arc<AtomicU64>, down_n: Arc<AtomicU64>) -> io::Result<()> {
    use tokio::io::AsyncWriteExt;
    up.write_all(&first).await?;
    up_n.fetch_add(first.len() as u64, Ordering::Relaxed);
    match side {
        #[cfg(target_os = "linux")]
        Side::Unix(b) => {
            let (r1, r2) = tokio::join!(sys::pump(&b, &up, &up_n), sys::pump(&up, &b, &down_n));
            r1.and(r2)
        }
        mut other => {
            let (u, d) = tokio::io::copy_bidirectional_with_sizes(&mut other, &mut up, CHUNK, CHUNK).await?;
            up_n.fetch_add(u, Ordering::Relaxed);
            down_n.fetch_add(d, Ordering::Relaxed);
            Ok(())
        }
    }
}

/// splice(2) from the event loop: each direction moves socket -> pipe -> socket without the bytes
/// entering userspace, waiting on the sockets' readiness rather than blocking a thread. A kernel
/// (or gVisor) that refuses to splice these sockets gets a read/write loop instead, for that
/// direction.
#[cfg(target_os = "linux")]
mod sys {
    use super::CHUNK;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::io::Interest;

    /// A tokio socket whose readiness can be awaited and whose fd can be used directly.
    pub(super) trait Sock: AsRawFd {
        async fn ready(&self, i: Interest) -> io::Result<()>;
        fn try_io<R>(&self, i: Interest, f: impl FnOnce() -> io::Result<R>) -> io::Result<R>;
    }

    macro_rules! sock {
        ($t:ty) => {
            impl Sock for $t {
                async fn ready(&self, i: Interest) -> io::Result<()> {
                    <$t>::ready(self, i).await.map(|_| ())
                }
                fn try_io<R>(&self, i: Interest, f: impl FnOnce() -> io::Result<R>) -> io::Result<R> {
                    <$t>::try_io(self, i, f)
                }
            }
        };
    }
    sock!(tokio::net::UnixStream);
    sock!(tokio::net::TcpStream);

    fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for the two descriptors pipe2 fills in.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: pipe2 succeeded; both are fresh descriptors owned by nothing else.
        let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        // SAFETY: F_SETPIPE_SZ takes an int; failure leaves the default size, which is fine.
        let _ = unsafe { libc::fcntl(fds[1], libc::F_SETPIPE_SZ, CHUNK as libc::c_int) };
        Ok((r, w))
    }

    fn splice(from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {
        loop {
            // SAFETY: null offsets are valid for pipes and sockets; the fds are borrowed for the call.
            let n = unsafe {
                libc::splice(from, std::ptr::null_mut(), to, std::ptr::null_mut(), len, libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK)
            };
            if n >= 0 {
                return Ok(n as usize);
            }
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::Interrupted {
                return Err(e);
            }
        }
    }

    fn refused(e: &io::Error) -> bool {
        matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP))
    }

    fn shut_write(fd: RawFd) {
        // SAFETY: shutdown on a borrowed socket fd; errors (already closed) don't matter.
        unsafe { libc::shutdown(fd, libc::SHUT_WR) };
    }

    /// Moves everything `from` sends to `to`, then half-closes `to`.
    pub(super) async fn pump<A: Sock, B: Sock>(from: &A, to: &B, n: &AtomicU64) -> io::Result<()> {
        let r = pump_inner(from, to, n).await;
        shut_write(to.as_raw_fd());
        r
    }

    async fn pump_inner<A: Sock, B: Sock>(from: &A, to: &B, n: &AtomicU64) -> io::Result<()> {
        let (pr, pw) = pipe()?;
        loop {
            from.ready(Interest::READABLE).await?;
            let got = match from.try_io(Interest::READABLE, || splice(from.as_raw_fd(), pw.as_raw_fd(), CHUNK)) {
                Ok(0) => return Ok(()),
                Ok(k) => k,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) if refused(&e) => return copy(from, to, n).await,
                Err(e) => return Err(e),
            };
            let mut left = got;
            while left > 0 {
                to.ready(Interest::WRITABLE).await?;
                match to.try_io(Interest::WRITABLE, || splice(pr.as_raw_fd(), to.as_raw_fd(), left)) {
                    Ok(k) => {
                        left -= k;
                        n.fetch_add(k as u64, Ordering::Relaxed);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(e) if refused(&e) => {
                        // The bytes are in the pipe: write them out the ordinary way, then copy.
                        drain(&pr, to, left, n).await?;
                        return copy(from, to, n).await;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }

    async fn write_all<B: Sock>(to: &B, mut buf: &[u8], n: &AtomicU64) -> io::Result<()> {
        while !buf.is_empty() {
            to.ready(Interest::WRITABLE).await?;
            // SAFETY: writes from a live buffer to a borrowed fd.
            let w = to.try_io(Interest::WRITABLE, || {
                let k = unsafe { libc::send(to.as_raw_fd(), buf.as_ptr().cast(), buf.len(), libc::MSG_NOSIGNAL) };
                if k < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(k as usize)
                }
            });
            match w {
                Ok(k) => {
                    buf = &buf[k..];
                    n.fetch_add(k as u64, Ordering::Relaxed);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    async fn drain<B: Sock>(pr: &OwnedFd, to: &B, mut left: usize, n: &AtomicU64) -> io::Result<()> {
        let mut buf = vec![0u8; left.min(CHUNK)];
        while left > 0 {
            // SAFETY: reads into a live buffer of the given length from our own pipe.
            let k = unsafe { libc::read(pr.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len().min(left)) };
            if k <= 0 {
                return Err(io::Error::last_os_error());
            }
            write_all(to, &buf[..k as usize], n).await?;
            left -= k as usize;
        }
        Ok(())
    }

    async fn copy<A: Sock, B: Sock>(from: &A, to: &B, n: &AtomicU64) -> io::Result<()> {
        let mut buf = vec![0u8; CHUNK];
        loop {
            from.ready(Interest::READABLE).await?;
            // SAFETY: reads into a live buffer from a borrowed fd.
            let r = from.try_io(Interest::READABLE, || {
                let k = unsafe { libc::recv(from.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
                if k < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(k as usize)
                }
            });
            match r {
                Ok(0) => return Ok(()),
                Ok(k) => write_all(to, &buf[..k], n).await?,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello as rustls sends it, for `name`.
    async fn hello_for(name: &str) -> Vec<u8> {
        // No roots: the handshake never gets past the hello.
        let cfg = rustls::ClientConfig::builder().with_root_certificates(rustls::RootCertStore::empty()).with_no_client_auth();
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let name = rustls::pki_types::ServerName::try_from(name.to_string()).unwrap();
        tokio::spawn(async move {
            let _ = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, &mut a).await;
        });
        let (raw, _) = read_hello(&mut b).await.unwrap();
        raw
    }

    #[tokio::test]
    async fn the_sni_of_a_real_client_hello_is_read() {
        let raw = hello_for("Static.Example").await;
        let (again, hello) = read_hello(&mut &raw[..]).await.unwrap();
        assert_eq!(again, raw);
        assert_eq!(hello, Some(Hello { sni: Some("static.example".into()), ech: false }));
        // Split across two records: still one hello.
        let body = &raw[5..];
        let (p, q) = body.split_at(body.len() / 2);
        let mut split = Vec::new();
        for part in [p, q] {
            split.extend_from_slice(&[22, 3, 1]);
            split.extend_from_slice(&(part.len() as u16).to_be_bytes());
            split.extend_from_slice(part);
        }
        assert_eq!(read_hello(&mut &split[..]).await.unwrap().1.unwrap().sni.as_deref(), Some("static.example"));
        // An IP address has no SNI.
        let raw = hello_for("192.0.2.1").await;
        assert_eq!(read_hello(&mut &raw[..]).await.unwrap().1.unwrap().sni, None);
    }

    #[tokio::test]
    async fn anything_but_a_client_hello_is_not_one() {
        for junk in [
            &b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            b"",
            b"\x16\x03\x01\x00",
            b"\x16\x03\x01\x00\x05\x02\x00\x00\x01\x00",
            b"SSH-2.0-x\r\n",
        ] {
            let (raw, hello) = read_hello(&mut &junk[..]).await.unwrap_or_default();
            assert!(hello.is_none(), "{junk:?}");
            assert!(junk.starts_with(&raw), "what was read is replayed as read");
        }
        // Truncated or garbled hello bodies parse to None, never panic.
        let raw = hello_for("static.example").await;
        let msg = &raw[5..];
        for cut in 0..msg.len() {
            let _ = parse_hello(&msg[..cut]);
        }
        let mut garbled = msg.to_vec();
        for i in 4..garbled.len() {
            garbled[i] ^= 0xff;
            let _ = parse_hello(&garbled);
            garbled[i] ^= 0xff;
        }
    }

    /// A hello with ECH, or with two names, doesn't qualify.
    #[test]
    fn ech_and_ambiguous_names_are_flagged() {
        let ext = |ty: u16, data: &[u8]| [&ty.to_be_bytes()[..], &(data.len() as u16).to_be_bytes(), data].concat();
        let sni = |names: &[&str]| {
            let mut list = Vec::new();
            for n in names {
                list.push(0u8);
                list.extend_from_slice(&(n.len() as u16).to_be_bytes());
                list.extend_from_slice(n.as_bytes());
            }
            [&(list.len() as u16).to_be_bytes()[..], &list].concat()
        };
        let hello = |exts: Vec<u8>| {
            let mut body = vec![3, 3];
            body.extend_from_slice(&[0; 32]);
            body.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
            body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
            body.extend_from_slice(&exts);
            let len = (body.len() as u32).to_be_bytes();
            [&[1u8, len[1], len[2], len[3]][..], &body].concat()
        };
        assert_eq!(parse_hello(&hello(ext(0, &sni(&["a.example"])))).unwrap(), Hello { sni: Some("a.example".into()), ech: false });
        assert_eq!(parse_hello(&hello(ext(0, &sni(&["a.example", "b.example"])))).unwrap().sni, None);
        assert_eq!(parse_hello(&hello([ext(0, &sni(&["a.example"])), ext(0, &sni(&["b.example"]))].concat())).unwrap().sni, None);
        assert!(parse_hello(&hello([ext(0, &sni(&["a.example"])), ext(0xfe0d, &[1, 2, 3])].concat())).unwrap().ech);
    }
}
