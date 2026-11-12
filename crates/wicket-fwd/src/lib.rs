//! wicket's in-box forwarder.
//!
//! A box runs with no network (`--network none`). Its only ways out are the unix sockets of wicket's
//! proxies, bind-mounted at `/wicket/sock/`. `wicket-entry` gives wicket its own address on the box's
//! loopback, `wicket.internal` = 198.18.0.1, and starts this forwarder as the agent's user with no
//! capabilities:
//!
//! ```text
//! wicket-fwd --listen 198.18.0.1:3128=/wicket/sock/egress.sock \
//!            --listen 198.18.0.1:8080=/wicket/sock/llm.sock \
//!            --listen 198.18.0.1:8081=/wicket/sock/gateway.sock
//! ```
//!
//! Each accepted TCP connection gets a new connection to its unix socket, and bytes are relayed both
//! ways. The forwarder enforces nothing: every decision is made by the proxies outside the box. It
//! replaces socat, which experiment #62 measured costing ~40 ms on most new connections (no
//! `TCP_NODELAY`, so Nagle meets delayed ACK) and holding gVisor downloads to 14 MB/s (an 8 KiB
//! buffer, where every read and write is a trapped syscall), and which forks per connection.
//!
//! # Behaviour
//!
//! - **One process, two threads per connection** (one per direction), blocking I/O, std only. A box
//!   holds a handful of connections at a time; threads keep half-close and errors simple, and need no
//!   runtime (and no TCP-only async runtime that would get in the way of UDP, below).
//! - **`TCP_NODELAY`** on every accepted socket.
//! - **Copying** ([`CopyMode`]): splice(2) through a 256 KiB pipe by default, falling back to
//!   read/write through a 256 KiB buffer when splice is refused (logged once); `--copy rw` forces
//!   read/write. Measured with `bench/box.sh` (curl in a `--network none` box, 1 KB GETs on new
//!   connections and 100 MB downloads, an origin on the host's unix socket; legs interleaved, the
//!   old socat image with this binary mounted in; shared 4 vCPU VPS, noisy), new connection p50 and
//!   download median, over three runs (2–3 rounds each, leg order rotated):
//!
//!   | box | socat (before) | `--copy rw` | `--copy splice` |
//!   |---|---|---|---|
//!   | gVisor (systrap) | 14–17 ms, 10–33 MB/s | 4.4–7.5 ms, 141–205 MB/s | 4.2–7.3 ms, 170–350 MB/s |
//!   | runc | 2.3 ms, 366 MB/s | 1.7 ms, 1,070 MB/s | 2.5 ms, 1,160 MB/s |
//!
//!   The two copy modes are within noise of each other in gVisor (which implements splice itself;
//!   whichever leg ran first in a round did best); splice is the default because it was ahead in
//!   runc and spends less CPU on the host kernel.
//! - **Half-close** propagates both ways: end of file on one side shuts down writing on the other, and
//!   the other direction carries on until its own end of file. An error in either direction (a reset,
//!   a broken pipe) shuts both sockets down completely, so neither thread is left blocked.
//! - **Bounded**: at most `--max-conns` connections (default 256) relay at once. At the limit each
//!   listener holds the connection it just accepted, and the kernel's backlog the ones behind it,
//!   until a connection finishes.
//! - **Logs** go to stderr, one line each: the listeners at start, errors (rate-limited per listener),
//!   the connection limit being hit, and the listen address disappearing or coming back. With
//!   `--verbose`, one line per connection: peer, bytes each way, duration. Never request contents.
//!
//! # The listen address
//!
//! At start, a listen address that isn't on any interface yet (`EADDRNOTAVAIL`: `wicket-entry` hasn't
//! added 198.18.0.1) is retried every 100 ms for up to `--bind-timeout` (default 5 s); any other bind
//! error is fatal at once. The process exits non-zero if a listener can't bind.
//!
//! Later, the address can disappear: a gVisor checkpoint/restore drops 198.18.0.1 from `lo`
//! (experiment #70). The listening sockets survive it, and accept again as soon as the address is
//! back; the forwarder has no `NET_ADMIN` and can't re-add it itself. Putting it back is
//! `wicket-entry --restore-hook`'s job, run by gVisor's save/restore hook as root inside the sandbox
//! before the box is woken (once wicket restores boxes from memory; today it parks them by
//! rebuild). So the forwarder doesn't die and doesn't rebind: a watcher thread checks
//! each listen address once a second (a UDP bind to it succeeds only while the address is local) and
//! logs `address 198.18.0.1 is gone` and `... is back`, so a missing hook shows up in the box's log
//! instead of as silent retries in the agent. `bench/addr-gone.sh` checks all of this in a gVisor box.
//!
//! # Datagrams, later (HTTP/3, DNS)
//!
//! Not built yet; the CLI and code are shaped for it. [`Kind`] gets a `Udp` variant and the CLI a
//! `--udp ADDR:PORT=PATH` (and `--udp *:443=PATH` for a wildcard socket), parsed by the same
//! [`spec::parse`]. Addresses on `lo` stay `wicket-entry`'s business (root only at start, the forwarder
//! never has `NET_ADMIN`): it puts the synthetic range wicket's DNS answers from (198.19.0.0/16, one
//! address per upstream host) on `lo` once, as a prefix, so every address in it is local without
//! adding them one by one (whether gVisor honours a prefix on `lo` is #92's spike); the forwarder
//! only listens.
//!
//! - **In the box.** One UDP socket per listener, or one wildcard `0.0.0.0:443` socket with
//!   `IP_PKTINFO` (`IPV6_RECVPKTINFO`) so each datagram's original destination is known even across
//!   many synthetic addresses; replies are sent with the same `IP_PKTINFO` so their source is the
//!   address the client sent to. A flow is (client addr:port, destination addr:port); the forwarder
//!   gives each a 32-bit id and forgets it after an idle timeout (QUIC's idle timeout, 30 s by default).
//! - **To the host.** One `SOCK_SEQPACKET` unix connection per UDP listener, falling back to
//!   `SOCK_DGRAM`: both keep datagram boundaries, so no length prefix is needed; seqpacket also tells
//!   each side when the other goes away. Every message is a fixed header then the payload:
//!   `version u8 (1) | kind u8 (0 data, 1 flow closed) | family u8 (4 or 6) | reserved u8 |
//!   flow id u32 | destination port u16 | client port u16 | destination address (16 bytes, v4-mapped)`
//!   (28 bytes, network byte order), then up to 65,507 payload bytes. Replies from the host carry the
//!   same header, so the forwarder knows which flow and source address to answer from. The client
//!   address stays in the box: the host only needs the flow id.
//! - **On the host** (#92): the relay terminates QUIC with wicket's CA, as the host name the
//!   synthetic destination address was minted for by wicket's DNS, and decides each HTTP/3 request
//!   like an HTTP/1 or HTTP/2 one. The forwarder needs no policy: it never sees a host name.
//! - **DNS** on 198.18.0.1:53: TCP DNS is an ordinary `--listen 198.18.0.1:53=/wicket/sock/dns.sock`
//!   today; UDP DNS is a `--udp 198.18.0.1:53=...` listener over the same framing, its answers
//!   (synthetic addresses in 198.19.0.0/16, NXDOMAIN for hidden hosts) decided on the host.
//! - **Not built here yet** because its other ends (the host relay, wicket's DNS, the synthetic
//!   addresses on `lo`) don't exist yet; it lands with them, for 0.0.1 (#92).

pub mod copy;
pub mod spec;
mod sys;

use std::io::{self, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub use copy::CopyMode;
pub use spec::{Kind, Listen};

/// Everything the forwarder runs with.
#[derive(Debug, Clone)]
pub struct Config {
    pub listens: Vec<Listen>,
    /// Connections relaying at once, over all listeners.
    pub max_conns: usize,
    pub copy: CopyMode,
    /// Buffer (read/write) or pipe (splice) size per direction.
    pub buf_size: usize,
    /// How long to wait at start for a listen address to appear.
    pub bind_timeout: Duration,
    /// How often to check that the listen addresses are still local (zero: never).
    pub watch_every: Duration,
    /// One log line per connection.
    pub verbose: bool,
    /// `--dial`: instead of listening, connect here and relay stdin/stdout ([`dial`]).
    pub dial: Option<SocketAddr>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listens: Vec::new(),
            max_conns: 256,
            copy: CopyMode::Splice,
            buf_size: 256 * 1024,
            bind_timeout: Duration::from_secs(5),
            watch_every: Duration::from_secs(1),
            verbose: false,
            dial: None,
        }
    }
}

/// Writes one line to stderr, prefixed. stderr is unbuffered; one `write_all` keeps lines whole.
pub fn log(msg: std::fmt::Arguments<'_>) {
    let line = format!("wicket-fwd: {msg}\n");
    let _ = io::stderr().lock().write_all(line.as_bytes());
}

macro_rules! log {
    ($($t:tt)*) => { $crate::log(format_args!($($t)*)) };
}

/// The running forwarder: the addresses it listens on (with any port 0 resolved).
pub struct Forwarder {
    pub addrs: Vec<SocketAddr>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl Forwarder {
    /// Binds every listener (waiting for missing addresses up to `bind_timeout`), then starts
    /// accepting. Fails if any listener can't bind; nothing is left running then.
    pub fn start(cfg: Config) -> io::Result<Forwarder> {
        spec::check_distinct(&cfg.listens).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut bound = Vec::new();
        for l in &cfg.listens {
            let listener = bind(l.addr, cfg.bind_timeout).map_err(|e| io::Error::new(e.kind(), format!("listen {}: {e}", l.addr)))?;
            bound.push((l.clone(), listener));
        }
        let cfg = Arc::new(cfg);
        let gate = Arc::new(Gate::new(cfg.max_conns));
        let mut addrs = Vec::new();
        let mut threads = Vec::new();
        for (l, listener) in bound {
            let addr = listener.local_addr()?;
            log!("listening {}", Listen { addr, ..l.clone() });
            addrs.push(addr);
            let (cfg, gate) = (cfg.clone(), gate.clone());
            threads.push(thread::Builder::new().name(format!("accept {addr}")).spawn(move || accept_loop(listener, l.path, cfg, gate))?);
        }
        if !cfg.watch_every.is_zero() {
            let mut ips: Vec<IpAddr> = addrs.iter().map(SocketAddr::ip).filter(|ip| !ip.is_unspecified()).collect();
            ips.dedup();
            let every = cfg.watch_every;
            threads.push(thread::Builder::new().name("watch".into()).spawn(move || watch(ips, every))?);
        }
        Ok(Forwarder { addrs, threads })
    }

    /// Blocks for as long as the forwarder runs (for good: accept loops never return).
    pub fn wait(self) {
        for t in self.threads {
            let _ = t.join();
        }
    }
}

fn bind(addr: SocketAddr, timeout: Duration) -> io::Result<TcpListener> {
    let start = Instant::now();
    let mut said = false;
    loop {
        // std sets SO_REUSEADDR on Unix listeners, as socat's `reuseaddr` did.
        match TcpListener::bind(addr) {
            Ok(l) => return Ok(l),
            Err(e) if e.kind() == io::ErrorKind::AddrNotAvailable && start.elapsed() < timeout => {
                if !said {
                    log!("waiting for address {} to appear", addr.ip());
                    said = true;
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e),
        }
    }
}

/// A counting semaphore: how many connections relay at once.
struct Gate {
    used: Mutex<usize>,
    freed: Condvar,
    max: usize,
    quiet: Mutex<Quiet>,
}

impl Gate {
    fn new(max: usize) -> Gate {
        Gate { used: Mutex::new(0), freed: Condvar::new(), max: max.max(1), quiet: Mutex::new(Quiet { last: None, dropped: 0 }) }
    }

    fn enter(self: &Arc<Self>) -> Permit {
        let mut used = self.used.lock().unwrap_or_else(|e| e.into_inner());
        if *used >= self.max {
            Quiet::say(&self.quiet, format_args!("at the connection limit ({}); new connections wait", self.max));
            while *used >= self.max {
                used = self.freed.wait(used).unwrap_or_else(|e| e.into_inner());
            }
        }
        *used += 1;
        Permit(self.clone())
    }
}

struct Permit(Arc<Gate>);

impl Drop for Permit {
    fn drop(&mut self) {
        *self.0.used.lock().unwrap_or_else(|e| e.into_inner()) -= 1;
        self.0.freed.notify_one();
    }
}

/// At most one error line per listener every few seconds; the count of the rest is reported.
struct Quiet {
    last: Option<Instant>,
    dropped: u64,
}

impl Quiet {
    fn say(q: &Mutex<Quiet>, msg: std::fmt::Arguments<'_>) {
        let mut q = q.lock().unwrap_or_else(|e| e.into_inner());
        if q.last.is_some_and(|t| t.elapsed() < Duration::from_secs(5)) {
            q.dropped += 1;
            return;
        }
        if q.dropped > 0 {
            log!("{msg} ({} similar errors not shown)", q.dropped);
        } else {
            log!("{msg}");
        }
        q.last = Some(Instant::now());
        q.dropped = 0;
    }
}

const THREAD_STACK: usize = 64 * 1024;

fn accept_loop(listener: TcpListener, path: PathBuf, cfg: Arc<Config>, gate: Arc<Gate>) {
    let quiet = Arc::new(Mutex::new(Quiet { last: None, dropped: 0 }));
    let ids = AtomicU64::new(0);
    loop {
        let (tcp, peer) = match listener.accept() {
            Ok(c) => c,
            Err(e) => {
                // EMFILE, ENOBUFS, ECONNABORTED: transient. Back off a little rather than spin.
                Quiet::say(&quiet, format_args!("accept on {}: {e}", listener.local_addr().map_or("?".into(), |a| a.to_string())));
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        // Accept first, then wait for a slot: a listener waiting in accept holds no slot, so a full
        // forwarder only delays this one connection (and the backlog behind it).
        let permit = gate.enter();
        let id = ids.fetch_add(1, Ordering::Relaxed);
        let (path, cfg, q) = (path.clone(), cfg.clone(), quiet.clone());
        let spawned = thread::Builder::new().stack_size(THREAD_STACK).name(format!("conn {id}")).spawn(move || {
            let _permit = permit;
            serve(tcp, peer, &path, &cfg, &q);
        });
        if let Err(e) = spawned {
            Quiet::say(&quiet, format_args!("starting a connection thread: {e}"));
        }
    }
}

fn serve(tcp: TcpStream, peer: SocketAddr, path: &Path, cfg: &Config, quiet: &Mutex<Quiet>) {
    let start = Instant::now();
    let _ = tcp.set_nodelay(true);
    let unix = match UnixStream::connect(path) {
        Ok(u) => u,
        Err(e) => {
            Quiet::say(quiet, format_args!("connect {}: {e}", path.display()));
            return; // dropping `tcp` closes the client's connection
        }
    };
    match relay(tcp, unix, cfg.copy, cfg.buf_size) {
        Ok((up, down)) if cfg.verbose => {
            log!("{peer} -> {}: {up} bytes up, {down} down, {} ms", path.display(), start.elapsed().as_millis())
        }
        Ok(_) => {}
        Err(e) if cfg.verbose => log!("{peer} -> {}: {e}", path.display()),
        Err(_) => {} // resets and broken pipes are ordinary ends
    }
}

/// Relays until both directions end; returns (bytes client to host, bytes host to client).
///
/// End of file on one side shuts down writing on the other (half-close). An error on either
/// direction shuts both sockets down entirely, which ends the other direction's blocking read.
pub fn relay(tcp: TcpStream, unix: UnixStream, mode: CopyMode, buf_size: usize) -> io::Result<(u64, u64)> {
    let (mut tcp_r, mut unix_w) = (tcp.try_clone()?, unix.try_clone()?);
    let up = thread::Builder::new().stack_size(THREAD_STACK).spawn(move || {
        let r = copy::copy(mode, &mut tcp_r, &mut unix_w, buf_size);
        end(&r, &tcp_r, &unix_w);
        r
    })?;
    let (mut unix_r, mut tcp_w) = (unix, tcp);
    let down = copy::copy(mode, &mut unix_r, &mut tcp_w, buf_size);
    end_down(&down, &unix_r, &tcp_w);
    let up = up.join().unwrap_or_else(|_| Err(io::Error::other("relay thread panicked")));
    Ok((up?, down?))
}

fn end(r: &io::Result<u64>, from: &TcpStream, to: &UnixStream) {
    match r {
        Ok(_) => {
            let _ = to.shutdown(Shutdown::Write);
        }
        Err(_) => {
            let _ = from.shutdown(Shutdown::Both);
            let _ = to.shutdown(Shutdown::Both);
        }
    }
}

fn end_down(r: &io::Result<u64>, from: &UnixStream, to: &TcpStream) {
    match r {
        Ok(_) => {
            let _ = to.shutdown(Shutdown::Write);
        }
        Err(_) => {
            let _ = from.shutdown(Shutdown::Both);
            let _ = to.shutdown(Shutdown::Both);
        }
    }
}

/// `--dial ADDR`: one TCP connection to `addr`, relayed to stdin and stdout, for a caller outside
/// the box that reaches in over `docker exec -i` (links between boxes, `wicket_proxy::link`: under
/// gVisor the host can't connect to a socket a box creates, so wicket runs this in the target box).
///
/// End of file on stdin shuts down writing on the connection (half-close); the call returns when the
/// connection's read side ends, without waiting for stdin. Returns (bytes in, bytes out).
pub fn dial(addr: SocketAddr, mode: CopyMode, buf_size: usize) -> io::Result<(u64, u64)> {
    use std::os::fd::AsFd;
    let tcp = TcpStream::connect(addr)?;
    let _ = tcp.set_nodelay(true);
    // Unbuffered handles on fds 0 and 1 (std's Stdin/Stdout buffer, and splice wants the fd).
    let mut stdin = std::fs::File::from(io::stdin().as_fd().try_clone_to_owned()?);
    let mut stdout = std::fs::File::from(io::stdout().as_fd().try_clone_to_owned()?);
    let mut tcp_w = tcp.try_clone()?;
    let up = thread::Builder::new().stack_size(THREAD_STACK).spawn(move || {
        let r = copy::copy(mode, &mut stdin, &mut tcp_w, buf_size);
        let _ = tcp_w.shutdown(if r.is_ok() { Shutdown::Write } else { Shutdown::Both });
        r
    })?;
    let mut tcp_r = tcp;
    let down = copy::copy(mode, &mut tcp_r, &mut stdout, buf_size);
    let _ = stdout.flush();
    let up = if up.is_finished() { up.join().unwrap_or(Ok(0)).unwrap_or(0) } else { 0 };
    Ok((up, down?))
}

/// Is `ip` an address of this machine (or box)? A UDP bind to it succeeds only then.
pub fn is_local(ip: IpAddr) -> bool {
    UdpSocket::bind((ip, 0)).is_ok()
}

fn watch(ips: Vec<IpAddr>, every: Duration) {
    let mut gone = vec![false; ips.len()];
    loop {
        thread::sleep(every);
        for (ip, gone) in ips.iter().zip(gone.iter_mut()) {
            let now_gone = !is_local(*ip);
            if now_gone != *gone {
                if now_gone {
                    log!("address {ip} is gone: listeners stay open and accept again once it is back (wicket-entry --restore-hook re-adds it)");
                } else {
                    log!("address {ip} is back");
                }
                *gone = now_gone;
            }
        }
    }
}
