//! Experiment #92: HTTP/3 egress for boxes. One static binary (musl), several roles:
//!
//! - `fwd`     in the box: UDP 443 (synthetic addresses) and DNS on wicket.internal:53 -> host.
//! - `term`    on the host: DNS for the box, QUIC + HTTP/3 termination, decision, upstream.
//! - `origin`  on the host: test origins (HTTP/3 + HTTP/2, and HTTP/2 only).
//! - `get`     HTTP/3 client (in the box, or on the host for the direct baseline).
//! - `resolve` getaddrinfo, as the box's programs see it.

mod certs;
mod client;
mod dns;
mod fwd;
mod origin;
mod term;
mod udpbench;
mod upstream;
mod wire;

use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;

struct Args {
    flags: HashMap<String, Vec<String>>,
    rest: Vec<String>,
}

impl Args {
    fn parse(v: &[String], switches: &[&str]) -> Args {
        let mut flags: HashMap<String, Vec<String>> = HashMap::new();
        let mut rest = Vec::new();
        let mut i = 0;
        while i < v.len() {
            if let Some(k) = v[i].strip_prefix("--") {
                if switches.contains(&k) {
                    flags.entry(k.into()).or_default().push("true".into());
                    i += 1;
                } else {
                    flags.entry(k.into()).or_default().push(v.get(i + 1).cloned().unwrap_or_default());
                    i += 2;
                }
            } else {
                rest.push(v[i].clone());
                i += 1;
            }
        }
        Args { flags, rest }
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.flags.get(k).and_then(|v| v.last()).map(|s| s.as_str())
    }
    fn req(&self, k: &str) -> Result<&str> {
        self.get(k).ok_or_else(|| anyhow!("--{k} is required"))
    }
    fn num<T: std::str::FromStr>(&self, k: &str, d: T) -> Result<T> {
        match self.get(k) {
            Some(s) => s.parse().map_err(|_| anyhow!("--{k}: bad number {s}")),
            None => Ok(d),
        }
    }
    fn has(&self, k: &str) -> bool {
        self.flags.contains_key(k)
    }
    fn map(&self, k: &str) -> Result<HashMap<String, SocketAddr>> {
        let mut m = HashMap::new();
        for e in self.flags.get(k).into_iter().flatten() {
            let (h, a) = e.split_once('=').ok_or_else(|| anyhow!("--{k} wants host=ip:port"))?;
            m.insert(h.to_string(), a.parse().with_context(|| format!("--{k} {e}"))?);
        }
        Ok(m)
    }
}

fn main() -> Result<()> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = argv.split_first().ok_or_else(|| anyhow!("usage: h3spike fwd|term|origin|get|resolve ..."))?;
    let a = Args::parse(rest, &["zero-rtt", "no-gso", "https-records", "no-migration", "quiet"]);
    let rt = || tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build();
    match cmd.as_str() {
        "fwd" => fwd::run(fwd::Opts {
            sock: a.get("sock").unwrap_or("/wicket/sock/udp.sock").into(),
            quic_port: a.num("port", 443)?,
            dns: a.get("dns").unwrap_or("198.18.0.1:53").parse()?,
            net: a.get("net").unwrap_or("198.19.0.0").parse()?,
            prefix: a.num("prefix", 16)?,
            batch: a.num("batch", 32)?,
            sockbuf: a.num("sockbuf", 4 << 20)?,
            gro: a.num("gro", 32)?,
        }),
        "term" => {
            let zone: wicket_core::ZoneSpec = serde_json::from_str(&std::fs::read_to_string(a.req("zone")?)?).context("zone JSON")?;
            rt()?.block_on(term::run(term::Opts {
                sock: a.req("sock")?.into(),
                zone,
                ca_out: a.req("ca-out")?.into(),
                origin_ca: a.req("origin-ca")?.into(),
                upstreams: a.map("upstream")?,
                audit: a.req("audit")?.into(),
                https_records: a.has("https-records"),
                migration: !a.has("no-migration"),
                mtu_upper: a.get("mtu-upper").map(|s| s.parse()).transpose()?,
                initial_mtu: a.get("initial-mtu").map(|s| s.parse()).transpose()?,
                idle_secs: a.num("idle", 30)?,
                gso: a.num("gso", 32)?,
            }))
        }
        "origin" => {
            let names = |k: &str| a.get(k).unwrap_or("").split(',').filter(|s| !s.is_empty()).map(String::from).collect::<Vec<_>>();
            rt()?.block_on(origin::run(
                a.req("ca-out")?,
                a.req("h3")?.parse()?,
                names("h3-names"),
                a.req("h2")?.parse()?,
                names("h2-names"),
            ))
        }
        "get" => {
            if a.rest.is_empty() {
                bail!("get: no URL");
            }
            rt()?.block_on(client::run(client::Opts {
                ca: a.req("ca")?.into(),
                connect: a.map("connect")?,
                urls: a.rest.clone(),
                n: a.num("n", 1)?,
                conns: a.num("conns", 1)?,
                zero_rtt: a.has("zero-rtt"),
                rebind_after: a.get("rebind-after").map(|s| s.parse()).transpose()?,
                pause_secs: a.num("pause", 0)?,
                mtu_upper: a.get("mtu-upper").map(|s| s.parse()).transpose()?,
                initial_mtu: a.get("initial-mtu").map(|s| s.parse()).transpose()?,
                gso: !a.has("no-gso"),
                idle_secs: a.num("idle", 30)?,
                method: a.get("method").unwrap_or("GET").into(),
                body_bytes: a.num("body", 0)?,
                quiet: a.has("quiet"),
                rcvbuf: a.get("rcvbuf").map(|s| s.parse()).transpose()?,
            }))
        }
        "resolve" => {
            client::resolve(&a.rest);
            Ok(())
        }
        "udpbench" => udpbench::run(
            a.get("send").unwrap_or("sendto"),
            a.get("recv").unwrap_or("one"),
            a.num("n", 100000)?,
            a.num("size", 1452)?,
            a.get("to").unwrap_or("198.19.0.5:9000").parse()?,
        ),
        c => bail!("unknown command {c}"),
    }
}
