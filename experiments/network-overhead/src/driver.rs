//! `netbench bench`: starts the origin once, then for each round and each setup starts that setup's
//! proxy chain, runs every workload, reads each process's CPU from /proc, and stops the chain.
//! Results go to `--out DIR/results.json`.

use crate::client::{self, Phases, Target};
use crate::Endpoint;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const ORIGIN: &str = "127.0.0.1:18443";
const HOP: &str = "127.0.0.1:18128";
const SNI: &str = "127.0.0.1:18129";

#[derive(Clone, Copy, PartialEq)]
enum Proxy {
    None,
    /// The egress proxy replica. `mem`: audit rows go to an in-memory ledger. `nopool`: no upstream keep-alive.
    Mitm { mem: bool, nopool: bool },
    /// CONNECT, host decision, SNI check, then copy.
    Pass { splice: bool },
    /// SNI only (no CONNECT), then copy.
    Sni { splice: bool },
}

#[derive(Clone, Copy, PartialEq)]
enum Hop {
    /// Straight to the proxy's unix socket (or the origin, or the SNI proxy's TCP port).
    Direct,
    /// socat as in wicket-entry: TCP-LISTEN,fork to UNIX-CONNECT. `nodelay`: with TCP_NODELAY on its listen side.
    Socat { nodelay: bool },
    /// This experiment's forwarder: one process, tokio copy or splice.
    Fwd { splice: bool },
}

struct Setup {
    name: &'static str,
    proxy: Proxy,
    hop: Hop,
    h2: bool,
}

fn setups() -> Vec<Setup> {
    use Hop::*;
    use Proxy::*;
    let s = |name, proxy, hop, h2| Setup { name, proxy, hop, h2 };
    vec![
        s("direct", None, Direct, false),
        s("direct-h2", None, Direct, true),
        s("mitm/unix", Mitm { mem: false, nopool: false }, Direct, false),
        s("mitm/socat", Mitm { mem: false, nopool: false }, Socat { nodelay: false }, false),
        s("mitm/socat-nodelay", Mitm { mem: false, nopool: false }, Socat { nodelay: true }, false),
        s("mitm/fwd", Mitm { mem: false, nopool: false }, Fwd { splice: false }, false),
        s("mitm-memaudit/unix", Mitm { mem: true, nopool: false }, Direct, false),
        s("mitm-nopool/unix", Mitm { mem: false, nopool: true }, Direct, false),
        s("pass/unix", Pass { splice: false }, Direct, false),
        s("pass/socat", Pass { splice: false }, Socat { nodelay: false }, false),
        s("pass-splice/unix", Pass { splice: true }, Direct, false),
        s("pass-splice/fwd-splice", Pass { splice: true }, Fwd { splice: true }, false),
        s("pass-h2/unix", Pass { splice: false }, Direct, true),
        s("sni/tcp", Sni { splice: false }, Direct, false),
        s("sni-splice/tcp", Sni { splice: true }, Direct, false),
    ]
}

pub fn stats_ns(sorted: &[u64]) -> Value {
    if sorted.is_empty() {
        return json!({ "n": 0 });
    }
    let q = |p: f64| sorted[((sorted.len() as f64 - 1.0) * p).round() as usize] as f64 / 1e3;
    let mean = sorted.iter().map(|&x| x as f64).sum::<f64>() / sorted.len() as f64 / 1e3;
    json!({ "n": sorted.len(), "p50_us": q(0.5), "p99_us": q(0.99), "mean_us": mean, "min_us": q(0.0), "max_us": q(1.0) })
}

pub fn stats_ns_unsorted(mut v: Vec<u64>) -> Value {
    v.sort_unstable();
    stats_ns(&v)
}

pub fn phases_json(ph: &[Phases]) -> Value {
    let f = |g: fn(&Phases) -> u64| stats_ns_unsorted(ph.iter().map(g).collect());
    json!({
        "connect": f(|p| p.connect),
        "proxy_connect": f(|p| p.proxy_connect),
        "tls": f(|p| p.tls),
        "ttfb": f(|p| p.ttfb),
        "total": f(|p| p.total),
    })
}

/// CPU seconds a process (and its reaped children) has used.
fn cpu_of(pid: u32) -> f64 {
    let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { return 0.0 };
    let rest = &s[s.rfind(')').unwrap_or(0) + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // Fields 14..17 of stat are 11..14 here (after pid and comm).
    let ticks: u64 = (11..15).filter_map(|i| f.get(i)?.parse::<u64>().ok()).sum();
    ticks as f64 / unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64
}

fn self_cpu() -> f64 {
    let mut r: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut r) };
    let tv = |t: libc::timeval| t.tv_sec as f64 + t.tv_usec as f64 / 1e6;
    tv(r.ru_utime) + tv(r.ru_stime)
}

struct Procs {
    named: Vec<(&'static str, Child)>,
}

impl Procs {
    fn cpu(&self) -> Vec<(&'static str, f64)> {
        let mut v: Vec<_> = self.named.iter().map(|(n, c)| (*n, cpu_of(c.id()))).collect();
        v.push(("client", self_cpu()));
        v
    }
    fn stop(mut self) {
        for (_, c) in self.named.iter_mut() {
            unsafe { libc::kill(c.id() as i32, libc::SIGTERM) };
        }
        for (_, c) in self.named.iter_mut() {
            let _ = c.wait();
        }
    }
}

fn cpu_delta(a: &[(&'static str, f64)], b: &[(&'static str, f64)]) -> Value {
    let mut m = serde_json::Map::new();
    for ((n, x), (_, y)) in a.iter().zip(b) {
        *m.entry(n.to_string()).or_insert(json!(0.0)) = json!(m.get(*n).and_then(Value::as_f64).unwrap_or(0.0) + (y - x));
    }
    m.into()
}

fn me() -> Result<PathBuf> {
    Ok(std::env::current_exe()?)
}

async fn wait_for(ep: &Endpoint) -> Result<()> {
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(10) {
        if crate::connect(ep).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    bail!("{ep:?} never came up")
}

async fn start(s: &Setup, work: &Path, stamps: &Path) -> Result<(Procs, Target)> {
    let exe = me()?;
    let sock = work.join("egress.sock");
    let origin_ca = std::fs::read(work.join("origin-ca.der"))?;
    let mut named = Vec::new();
    let port = "18443";
    let mut tls_ca = origin_ca.clone();
    let mut ep = Endpoint::Unix(sock.clone());
    let mut connect = true;
    match s.proxy {
        Proxy::None => {
            ep = Endpoint::Tcp(ORIGIN.parse()?);
            connect = false;
        }
        Proxy::Mitm { mem, nopool } => {
            let ledger = work.join("ledger.db");
            for ext in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{ext}", ledger.display()));
            }
            let _ = std::fs::remove_file(work.join("run-ca.pem"));
            let mut c = Command::new(&exe);
            c.args(["mitm", "--listen", &format!("unix:{}", sock.display()), "--dir", &work.display().to_string(), "--upstream-port", port]);
            c.args(["--ledger", &if mem { ":memory:".into() } else { ledger.display().to_string() }, "--stamps", &stamps.display().to_string()]);
            if nopool {
                c.arg("--no-pool");
            }
            named.push(("proxy", c.spawn()?));
            wait_for(&Endpoint::Unix(sock.clone())).await?;
            let pem = std::fs::read_to_string(work.join("run-ca.pem"))?;
            tls_ca = pem_to_der(&pem)?;
        }
        Proxy::Pass { splice } | Proxy::Sni { splice } => {
            let sni = matches!(s.proxy, Proxy::Sni { .. });
            let listen = if sni { format!("tcp:{SNI}") } else { format!("unix:{}", sock.display()) };
            let mut c = Command::new(&exe);
            c.args(["pass", "--listen", &listen, "--mode", if sni { "sni" } else { "connect" }, "--upstream-port", port]);
            c.args(["--copy", if splice { "splice" } else { "tokio" }, "--stamps", &stamps.display().to_string()]);
            named.push(("proxy", c.spawn()?));
            if sni {
                ep = Endpoint::Tcp(SNI.parse()?);
                connect = false;
            }
            wait_for(&ep).await?;
        }
    }
    match s.hop {
        Hop::Direct => {}
        Hop::Socat { nodelay } => {
            let c = Command::new("socat")
                .args([format!("TCP-LISTEN:{},bind=127.0.0.1,fork,reuseaddr{}", HOP.rsplit(':').next().unwrap(), if nodelay { ",nodelay" } else { "" }), format!("UNIX-CONNECT:{}", sock.display())])
                .spawn()?;
            named.push(("hop", c));
            ep = Endpoint::Tcp(HOP.parse()?);
            wait_for(&ep).await?;
        }
        Hop::Fwd { splice } => {
            let c = Command::new(&exe)
                .args(["fwd", "--listen", &format!("tcp:{HOP}"), "--to", &format!("unix:{}", sock.display()), "--copy", if splice { "splice" } else { "tokio" }])
                .spawn()?;
            named.push(("hop", c));
            ep = Endpoint::Tcp(HOP.parse()?);
            wait_for(&ep).await?;
        }
    }
    let alpn: &[&[u8]] = if s.h2 { &[b"h2"] } else { &[b"http/1.1"] };
    Ok((Procs { named }, Target { ep, connect, tls: crate::client_tls(&tls_ca, alpn)?, h2: s.h2 }))
}

pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    Ok(base64::engine::general_purpose::STANDARD.decode(b64)?)
}

pub async fn run() -> Result<()> {
    let out = PathBuf::from(crate::arg("--out").unwrap_or_else(|| "logs".into()));
    let work = PathBuf::from(crate::arg("--work").unwrap_or_else(|| "target/run".into()));
    let rounds: usize = crate::arg("--rounds").map(|r| r.parse()).transpose()?.unwrap_or(3);
    let only = crate::arg("--only");
    let big: u64 = crate::arg("--big").map(|r| r.parse()).transpose()?.unwrap_or(100_000_000);
    let secs: u64 = crate::arg("--secs").map(|r| r.parse()).transpose()?.unwrap_or(4);
    std::fs::create_dir_all(&out)?;
    std::fs::create_dir_all(&work)?;
    let work = work.canonicalize()?;
    let _ = std::fs::remove_file(work.join("origin-ca.der"));
    let mut origin = Command::new(me()?).args(["origin", "--listen", ORIGIN, "--dir", &work.display().to_string()]).spawn()?;
    wait_for(&Endpoint::Tcp(ORIGIN.parse()?)).await?;
    let mut results = serde_json::Map::new();
    let res = async {
        for round in 0..rounds {
            for s in setups() {
                if only.as_deref().is_some_and(|o| !s.name.contains(o)) {
                    continue;
                }
                eprintln!("round {round}: {}", s.name);
                let stamps = work.join("stamps.json");
                let _ = std::fs::remove_file(&stamps);
                let (procs, t) = start(&s, &work, &stamps).await.with_context(|| s.name)?;
                let origin_cpu = |v: &mut Vec<(&'static str, f64)>| v.push(("origin", cpu_of(origin.id())));
                let snap = |p: &Procs| {
                    let mut v = p.cpu();
                    origin_cpu(&mut v);
                    v
                };
                let mut r = serde_json::Map::new();
                client::lat_keep(&t, 0, 50, "/1k").await?; // warm: leaf minted, upstream pool filled
                r.insert("lat_new".into(), phases_json(&client::lat_new(&t, 150, "/1k").await?));
                r.insert("lat_keep".into(), stats_ns_unsorted(client::lat_keep(&t, 1000, 50, "/1k").await?));
                for (name, keep) in [("rps_keep", true), ("rps_new", false)] {
                    let a = snap(&procs);
                    let (n, lat) = client::rps(&t, 16, Duration::from_secs(secs), keep, "/1k").await?;
                    let b = snap(&procs);
                    r.insert(name.into(), json!({ "requests": n, "rps": n as f64 / secs as f64, "lat": stats_ns_unsorted(lat), "cpu_s": cpu_delta(&a, &b) }));
                }
                let a = snap(&procs);
                let mut secs_v = Vec::new();
                for _ in 0..3 {
                    secs_v.push(client::download(&t, big).await?);
                }
                let b = snap(&procs);
                r.insert("download".into(), json!({ "bytes": big, "secs": secs_v, "cpu_s": cpu_delta(&a, &b) }));
                let mut up = Vec::new();
                for _ in 0..3 {
                    up.push(client::upload(&t, 10_000_000).await?);
                }
                r.insert("upload_10mb_secs".into(), json!(up));
                procs.stop();
                if let Ok(st) = std::fs::read_to_string(&stamps) {
                    r.insert("proxy_stamps".into(), serde_json::from_str(&st)?);
                }
                results.entry(s.name.to_string()).or_insert_with(|| json!([])).as_array_mut().unwrap().push(Value::Object(r));
                std::fs::write(out.join("results.json"), serde_json::to_string_pretty(&results)?)?;
            }
        }
        anyhow::Ok(())
    }
    .await;
    unsafe { libc::kill(origin.id() as i32, libc::SIGTERM) };
    let _ = origin.wait();
    res
}
