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
//!            --listen 198.18.0.1:8081=/wicket/sock/gateway.sock \
//!            --udp 0.0.0.0:443=/wicket/sock/udp.sock --udp 198.18.0.1:53=/wicket/sock/udp.sock
//! ```
//!
//! With `--control` ([`entry`]), it also does the agent user's part of the box's start (its
//! directories, the CA bundle) and tells `wicket-entry` over a pipe when every listener is bound,
//! so the box's start neither polls for it nor spawns a process per step (#287).
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
//! # Datagrams (HTTP/3 and DNS, #92)
//!
//! `--udp ADDR:PORT=PATH` listeners relay datagrams in [`frame`]s; see [`udp`] for the details.
//! `wicket-entry` starts two, both to `/wicket/sock/udp.sock`:
//!
//! ```text
//! --udp 0.0.0.0:443=/wicket/sock/udp.sock      # QUIC to any synthetic address (198.19.0.0/16 on lo)
//! --udp 198.18.0.1:53=/wicket/sock/udp.sock    # DNS: the box's resolver
//! ```
//!
//! wicket's DNS answers every allowed host with a synthetic address in 198.19.0.0/16 (and hidden
//! hosts with NXDOMAIN); `wicket-entry` puts that whole range on `lo` as one address with a /16
//! prefix (gVisor makes the prefix local; it refuses `ip route add local`). The forwarder never sees
//! a host name and decides nothing: the host terminates QUIC as the name the address was minted for.
//!
//! The frame is stateless (both addresses in every frame, both ways) rather than flow ids, so the
//! forwarder has no flow table to expire and QUIC migration needs nothing from it. The host side is
//! `wicket_proxy::h3`.

pub mod copy;
pub mod entry;
pub mod frame;
pub mod spec;
pub mod stdin;
mod sys;
pub mod udp;

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
    /// `--dial`'s limits (`--idle-secs`, `--after-close-secs`; [`dial_bounded`]).
    pub dial_limits: DialLimits,
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
            dial_limits: DialLimits::default(),
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
        let mut udp = Vec::new();
        for l in cfg.listens.iter().filter(|l| l.kind == Kind::Udp) {
            let s = udp::bind(l.addr, cfg.bind_timeout).map_err(|e| io::Error::new(e.kind(), format!("udp {}: {e}", l.addr)))?;
            udp.push((l.clone(), s));
        }
        for l in cfg.listens.iter().filter(|l| l.kind == Kind::Tcp) {
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
        for (l, sock) in udp {
            let addr = sock.local_addr()?;
            log!("listening {}", Listen { addr, ..l.clone() });
            addrs.push(addr);
            let verbose = cfg.verbose;
            threads.push(thread::Builder::new().name(format!("udp {addr}")).spawn(move || udp::serve(sock, l.path, verbose))?);
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
/// connection's read side ends, without waiting for stdin. Returns (bytes in, bytes out). With no
/// [`DialLimits`], as links run it: a service that ignores the half-close keeps it running.
pub fn dial(addr: SocketAddr, mode: CopyMode, buf_size: usize) -> io::Result<(u64, u64)> {
    dial_bounded(addr, mode, buf_size, DialLimits::default())
}

/// How long a `--dial` relay may last (#796 re-review, H2), each off unless given: a node's host
/// port (`--idle-secs`, `--after-close-secs`) gives both, so a peer on the internet that sends a
/// byte and goes can't leave a `wicket-fwd` in the box for as long as the box's service keeps its
/// side open. Links between boxes give neither: they are long-lived and rely on half-close.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct DialLimits {
    /// No bytes either way for this long: the relay ends.
    pub idle: Option<Duration>,
    /// This long after stdin's end of file, the relay ends even if the box's side stays open.
    pub after_close: Option<Duration>,
}

/// How long [`dial_bounded`] waits, after a limit shut its connection down, for its copy to see it,
/// before it ends the process: a copy blocked writing to stdout (its reader stopped reading)
/// doesn't see the connection's shutdown.
const DIAL_GRACE: Duration = Duration::from_secs(2);

/// [`dial`], ended by `limits`: when one passes, the connection is shut down both ways (which ends
/// the copy reading it), and if the copy is stuck writing to stdout, the process exits
/// ([`DIAL_GRACE`] later; `--dial` is the whole process).
pub fn dial_bounded(addr: SocketAddr, mode: CopyMode, buf_size: usize, limits: DialLimits) -> io::Result<(u64, u64)> {
    use std::os::fd::AsFd;
    use std::sync::mpsc;
    let tcp = TcpStream::connect(addr)?;
    let _ = tcp.set_nodelay(true);
    // Unbuffered handles on fds 0 and 1 (std's Stdin/Stdout buffer, and splice wants the fd).
    let mut stdin = std::fs::File::from(io::stdin().as_fd().try_clone_to_owned()?);
    let mut stdout = std::fs::File::from(io::stdout().as_fd().try_clone_to_owned()?);
    let started = Instant::now();
    let ms = move || started.elapsed().as_millis() as u64;
    // When bytes last moved either way, and when stdin ended (u64::MAX: not yet), in ms since start.
    let last = Arc::new(AtomicU64::new(0));
    let closed = Arc::new(AtomicU64::new(u64::MAX));
    // Wakes the watchdog when stdin ends or this call returns; `done` (set before the latter) ends
    // it, so a watchdog never acts once the relay is over.
    let (wake, woken) = mpsc::channel::<()>();
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    if limits != DialLimits::default() {
        let (tcp, last, closed, done) = (tcp.try_clone()?, last.clone(), closed.clone(), done.clone());
        let over = move || done.load(Ordering::SeqCst);
        thread::Builder::new().stack_size(THREAD_STACK).spawn(move || {
            let why = loop {
                if over() {
                    return;
                }
                let now = ms();
                let idle = limits.idle.map(|d| (last.load(Ordering::SeqCst) + d.as_millis() as u64, "idle"));
                let c = closed.load(Ordering::SeqCst);
                let after = limits.after_close.filter(|_| c != u64::MAX).map(|d| (c + d.as_millis() as u64, "stdin closed"));
                let next = [idle, after].into_iter().flatten().min_by_key(|(at, _)| *at);
                let got = match next {
                    Some((at, why)) if at <= now => break why,
                    Some((at, _)) => woken.recv_timeout(Duration::from_millis(at - now)),
                    None => woken.recv().map_err(|_| mpsc::RecvTimeoutError::Disconnected),
                };
                if got == Err(mpsc::RecvTimeoutError::Disconnected) {
                    return;
                }
            };
            if over() {
                return;
            }
            log!("dial {addr}: {why} past its limit; closing");
            let _ = tcp.shutdown(Shutdown::Both);
            // Still running after the grace: the copy is stuck on stdout.
            let until = Instant::now() + DIAL_GRACE;
            while let Some(left) = until.checked_duration_since(Instant::now()) {
                if over() || woken.recv_timeout(left) == Err(mpsc::RecvTimeoutError::Disconnected) {
                    return;
                }
            }
            if !over() {
                std::process::exit(0);
            }
        })?;
    }
    let mut tcp_w = tcp.try_clone()?;
    let (up_last, up_wake) = (last.clone(), wake.clone());
    let up = thread::Builder::new().stack_size(THREAD_STACK).spawn(move || {
        let r = copy::copy_with(mode, &mut stdin, &mut tcp_w, buf_size, &|_| up_last.store(ms(), Ordering::SeqCst));
        let _ = tcp_w.shutdown(if r.is_ok() { Shutdown::Write } else { Shutdown::Both });
        closed.store(ms(), Ordering::SeqCst);
        let _ = up_wake.send(());
        r
    })?;
    let mut tcp_r = tcp;
    let down = copy::copy_with(mode, &mut tcp_r, &mut stdout, buf_size, &|_| last.store(ms(), Ordering::SeqCst));
    let _ = stdout.flush();
    done.store(true, Ordering::SeqCst);
    let _ = wake.send(());
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
