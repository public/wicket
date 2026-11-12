//! Experiment #62: what wicket's egress proxy costs per request and per byte, and where the time goes.
//!
//! One binary, one role per process, so each process's CPU can be read from /proc:
//!
//!   netbench origin --listen ADDR --dir DIR          HTTPS origin for `origin.test` (h1 + h2), writes DIR/origin-ca.der
//!   netbench mitm   --listen unix:P --dir DIR ...    replica of wicket's egress proxy data path (egress.rs at 727e50f)
//!   netbench egress --listen unix:P --dir DIR ...    wicket's real egress proxy (splices origin.test; --inspect: doesn't)
//!   netbench pass   --listen unix:P|tcp:A ...        host-only check, then splice-through (the #62 fast path)
//!   netbench fwd    --listen tcp:A --to unix:P       a forwarder in place of socat
//!   netbench bench  --out logs/                      starts the processes and runs every leg
//!   netbench micro                                   leaf minting, decision and audit-write costs in-process
//!   netbench probe  ...                              one client run (used inside a gVisor box)

mod client;
mod driver;
mod egress;
mod micro;
mod mitm;
mod origin;
mod pass;
mod splice;

use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use wicket_core::{CompiledZone, Manifest};

/// The origin's name. The bench zone lists it like any public host.
pub const ORIGIN_HOST: &str = "origin.test";

pub fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

pub fn flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

pub fn need(name: &str) -> Result<String> {
    arg(name).with_context(|| format!("missing {name}"))
}

/// Where a process listens or a client connects.
#[derive(Clone, Debug)]
pub enum Endpoint {
    Unix(PathBuf),
    Tcp(SocketAddr),
}

impl Endpoint {
    pub fn parse(s: &str) -> Result<Endpoint> {
        if let Some(p) = s.strip_prefix("unix:") {
            Ok(Endpoint::Unix(p.into()))
        } else if let Some(a) = s.strip_prefix("tcp:") {
            Ok(Endpoint::Tcp(a.parse()?))
        } else {
            bail!("endpoint {s:?}: want unix:PATH or tcp:ADDR")
        }
    }
}

pub trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Io for T {}

pub async fn connect(ep: &Endpoint) -> Result<Box<dyn Io>> {
    Ok(match ep {
        Endpoint::Unix(p) => Box::new(tokio::net::UnixStream::connect(p).await?),
        Endpoint::Tcp(a) => {
            let s = tokio::net::TcpStream::connect(a).await?;
            s.set_nodelay(true)?;
            Box::new(s)
        }
    })
}

/// The bench zone (zone.yaml next to Cargo.toml), compiled as a run compiles its zone.
pub fn zone() -> Result<Arc<CompiledZone>> {
    let path = arg("--zone").unwrap_or_else(|| concat!(env!("CARGO_MANIFEST_DIR"), "/zone.yaml").into());
    let m = Manifest::from_yaml(&std::fs::read_to_string(&path).with_context(|| path.clone())?)?;
    Ok(Arc::new(CompiledZone::new(m.zone)?))
}

/// One TLS client config per trust root and ALPN list. Resumption is off: most tools in a box are short
/// processes that start with an empty session cache, so every new connection pays a full handshake.
pub fn client_tls(ca_der: &[u8], alpn: &[&[u8]]) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(ca_der.to_vec()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg =
        rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions()?.with_root_certificates(roots).with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    cfg.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(cfg))
}

fn main() -> Result<()> {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let threads: usize = arg("--threads").map(|t| t.parse()).transpose()?.unwrap_or(4);
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(threads).enable_all().build()?;
    match cmd.as_str() {
        "origin" => rt.block_on(origin::run(need("--listen")?.parse()?, need("--dir")?.into())),
        "mitm" => rt.block_on(mitm::run()),
        "egress" => rt.block_on(egress::run()),
        "pass" => rt.block_on(pass::run()),
        "fwd" => rt.block_on(pass::fwd()),
        "bench" => rt.block_on(driver::run()),
        "micro" => micro::run(),
        "probe" => rt.block_on(client::probe()),
        _ => bail!("usage: netbench origin|mitm|egress|pass|fwd|bench|micro|probe ... (see src/main.rs)"),
    }
}

/// Stage timings a proxy records (ns), dumped as JSON when it gets SIGTERM.
pub mod stamps {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    static STAMPS: Mutex<Option<BTreeMap<&'static str, Vec<u64>>>> = Mutex::new(None);

    pub fn add(stage: &'static str, d: std::time::Duration) {
        let mut s = STAMPS.lock().unwrap();
        s.get_or_insert_with(BTreeMap::new).entry(stage).or_default().push(d.as_nanos() as u64);
    }

    pub fn summary() -> serde_json::Value {
        let s = STAMPS.lock().unwrap();
        let mut out = serde_json::Map::new();
        for (k, v) in s.iter().flatten() {
            let mut v = v.clone();
            v.sort_unstable();
            out.insert(k.to_string(), crate::driver::stats_ns(&v));
        }
        out.into()
    }

    /// On SIGTERM: write the summary to `--stamps FILE` (if given) and exit.
    pub fn dump_on_sigterm() {
        tokio::spawn(async {
            let mut sig = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("signal");
            sig.recv().await;
            if let Some(f) = crate::arg("--stamps") {
                let _ = std::fs::write(f, serde_json::to_string_pretty(&summary()).unwrap());
            }
            std::process::exit(0);
        });
    }
}
