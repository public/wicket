//! In-process costs of the proxy's per-host and per-request steps: leaf minting (`RunCa::server_config`,
//! first call and cached), a TLS handshake in memory, the decision, and the audit row.

use anyhow::Result;
use serde_json::json;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;
use wicket_core::{canonical_path, Op, RunId, TenantId};
use wicket_proxy::ca::RunCa;
use wicket_store::Ledger;

fn time<T>(n: usize, mut f: impl FnMut(usize) -> T) -> serde_json::Value {
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        let t = Instant::now();
        black_box(f(i));
        v.push(t.elapsed().as_nanos() as u64);
    }
    crate::driver::stats_ns_unsorted(v)
}

/// One full TLS 1.3 handshake between a rustls client and server in memory (both sides' CPU).
fn handshake(server: &Arc<rustls::ServerConfig>, client: &Arc<rustls::ClientConfig>, host: &str) -> Result<()> {
    let mut c = rustls::ClientConnection::new(client.clone(), rustls::pki_types::ServerName::try_from(host.to_string())?)?;
    let mut s = rustls::ServerConnection::new(server.clone())?;
    let mut buf = Vec::new();
    while c.is_handshaking() || s.is_handshaking() {
        buf.clear();
        while c.wants_write() {
            c.write_tls(&mut buf)?;
        }
        let mut rd = &buf[..];
        while !rd.is_empty() {
            s.read_tls(&mut rd)?;
        }
        s.process_new_packets()?;
        buf.clear();
        while s.wants_write() {
            s.write_tls(&mut buf)?;
        }
        let mut rd = &buf[..];
        while !rd.is_empty() {
            c.read_tls(&mut rd)?;
        }
        c.process_new_packets()?;
    }
    Ok(())
}

pub fn run() -> Result<()> {
    let ca = RunCa::generate("run_micro")?;
    let mut out = serde_json::Map::new();
    out.insert("keypair_generate_p256".into(), time(300, |_| rcgen::KeyPair::generate().unwrap()));
    out.insert("leaf_first_mint".into(), time(300, |i| ca.server_config(&format!("h{i}.example.com")).unwrap()));
    out.insert("leaf_cached".into(), time(100_000, |i| ca.server_config(&format!("h{}.example.com", i % 300)).unwrap()));

    // Handshake: a box's client against the proxy's minted leaf.
    let server = ca.server_config("origin.test")?;
    let pem = ca.cert_pem();
    let der = {
        use base64::Engine;
        let b: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        base64::engine::general_purpose::STANDARD.decode(b)?
    };
    let client = crate::client_tls(&der, &[b"http/1.1"])?;
    out.insert("tls13_handshake_both_sides".into(), time(500, |_| handshake(&server, &client, "origin.test").unwrap()));

    let zone = crate::zone()?;
    let (t, r) = (TenantId::single(), RunId("run_micro".into()));
    out.insert(
        "decide_canonical_op_evaluate".into(),
        time(200_000, |_| {
            let pq = "/bytes/1024?x=1";
            let path = canonical_path(pq).unwrap().to_string();
            let op = Op::egress_with_query(&t, &r, &zone.name, "GET", "origin.test", &path, "x=1");
            zone.evaluate(&op)
        }),
    );
    out.insert("host_verdict".into(), time(200_000, |_| zone.host_verdict("origin.test")));
    out.insert("needs_inspection".into(), time(200_000, |_| crate::pass::needs_inspection(&zone, "origin.test")));

    let ev = json!({ "kind": "egress", "method": "GET", "host": "origin.test", "path": "/1k", "risk": "R1ReadScoped", "outcome": "allow", "detail": "reach rule 4" });
    let dir = std::path::PathBuf::from(crate::arg("--work").unwrap_or_else(|| "target/run".into()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("micro-ledger.db");
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }
    let l = Ledger::open(&path)?;
    out.insert("audit_row_file_ledger".into(), time(3000, |_| l.audit(&t, Some(&r), "op", &ev).unwrap()));
    let m = Ledger::open_in_memory()?;
    out.insert("audit_row_memory_ledger".into(), time(3000, |_| m.audit(&t, Some(&r), "op", &ev).unwrap()));
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
