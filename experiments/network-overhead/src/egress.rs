//! `netbench egress`: wicket's real egress proxy (`wicket_proxy::egress::Egress`), as `wicket run`
//! starts it: a file ledger with the batched audit writer, the run's CA, the central decider. Only
//! the upstream is the harness's: `origin.test` is pinned to the local origin and its CA trusted
//! (`Upstream::resolve` and `roots_pem`, as the proxy's own tests do).
//!
//! The bench zone allows `origin.test` wholesale, so the proxy splices it through (#62). `--inspect`
//! adds a forbid rule on a path the bench never asks for, which makes the same zone inspected: the
//! before and after of splice-through, on the same code.

use anyhow::Result;
use std::sync::{Arc, Mutex};
use wicket_core::{CompiledZone, RunId, TenantId};
use wicket_proxy::ca::RunCa;
use wicket_proxy::decide::Central;
use wicket_proxy::egress::{Egress, Upstream};
use wicket_proxy::RunCtx;
use wicket_store::Ledger;

pub async fn run() -> Result<()> {
    let listen = match crate::Endpoint::parse(&crate::need("--listen")?)? {
        crate::Endpoint::Unix(p) => p,
        _ => anyhow::bail!("egress listens on a unix socket"),
    };
    let dir = std::path::PathBuf::from(crate::need("--dir")?);
    let port: u16 = crate::need("--upstream-port")?.parse()?;
    let origin_ca = std::fs::read(dir.join("origin-ca.der"))?;
    let run = RunId("run_netbench".into());
    let ca = Arc::new(RunCa::generate(&run.0)?);
    std::fs::write(dir.join("run-ca.pem"), ca.cert_pem())?;
    let mut ledger = Ledger::open(std::path::Path::new(&crate::need("--ledger")?))?;
    ledger.start_audit_writer(None)?;
    let mut spec = crate::zone()?.spec().clone();
    if crate::flag("--inspect") {
        spec.forbid.push(serde_json::from_value(serde_json::json!({ "host": crate::ORIGIN_HOST, "paths": ["/never/**"] }))?);
    }
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    // The run drains events to its console; here they are dropped.
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    let ctx = RunCtx {
        tenant: TenantId::single(),
        run,
        zone: Arc::new(CompiledZone::new(spec)?),
        ledger: Arc::new(Mutex::new(ledger)),
        vault: wicket_proxy::vault::Vault::new(dir.join("vault")),
        events: tx,
        escalate: true,
        attribute: None,
        identity: None,
        spawner: None,
        swaps: vec![],
        boxes: None,
        capacity: None,
        fence: None,
        waker: None,
    };
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &origin_ca)
    );
    let mut up = Upstream { roots_pem: Some(pem), ..Default::default() };
    up.resolve.insert(crate::ORIGIN_HOST.into(), ([127, 0, 0, 1], port).into());
    let egress = Egress::with_upstream(ctx, ca, Arc::new(Central), None, up)?;
    egress.serve(&listen).await
}
