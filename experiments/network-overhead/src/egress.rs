//! `netbench egress`: wicket's real egress proxy (`wicket_proxy::egress::Egress`), as `wicket run`
//! starts it: a file ledger with the batched audit writer, the run's CA, the central decider. Only
//! the upstream is the harness's: `origin.test` is pinned to the local origin and its CA trusted
//! (`Upstream::resolve` and `roots_pem`, as the proxy's own tests do).
//!
//! The bench zone allows `origin.test` wholesale, so the proxy splices it through (#62). `--inspect`
//! adds a forbid rule on a path the bench never asks for, which makes the same zone inspected: the
//! before and after of splice-through, on the same code.
//!
//! `--upstream-h1` keeps the proxy's upstream connections on HTTP/1.1 although the origin offers
//! HTTP/2 (the before of #142's pooling). `--node` decides as a remote node does (#141): a
//! `NodeDecider` over a feed replica holding the run's token, kept fresh by a statement every 5 s as
//! a connected node's would be.

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
        org: None,
    };
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &origin_ca)
    );
    let mut up = Upstream { roots_pem: Some(pem), http1_only: crate::flag("--upstream-h1"), ..Default::default() };
    up.resolve.insert(crate::ORIGIN_HOST.into(), ([127, 0, 0, 1], port).into());
    let decider: Arc<dyn wicket_proxy::decide::Decider> =
        if crate::flag("--node") { node_decider(ctx.zone.spec(), &dir)? } else { Arc::new(Central) };
    let egress = Egress::with_upstream(ctx, ca, decider, None, up)?;
    egress.serve(&listen).await
}

/// A node's decider for run_netbench: its token minted from `zone`, in a replica fed in-process and
/// refreshed every 5 s (the feed's lease is 30 s).
fn node_decider(zone: &wicket_core::ZoneSpec, dir: &std::path::Path) -> Result<Arc<dyn wicket_proxy::decide::Decider>> {
    use ed25519_dalek::SigningKey;
    use wicket_feed::{Change, Issuer, KeyCert, Publisher, PublisherConfig, Replica, ReplicaConfig};
    let now_ms = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
    let root = SigningKey::from_bytes(&[7; 32]);
    let key = SigningKey::from_bytes(&[8; 32]);
    let authz_root = wicket_authz::SigningKey::from_bytes(&[9; 32])?;
    let approver = wicket_authz::SigningKey::from_bytes(&[10; 32])?;
    let cert = KeyCert::new(&key.verifying_key(), 1, i64::MAX / 2, 30_000);
    let cert_jws = wicket_feed::sign(&root, wicket_feed::TYP_KEY, &cert);
    let cfg = PublisherConfig { ttl_ms: 30_000, refresh_ms: 5_000, retain: 100 };
    let feed = dir.join("feed");
    let _ = std::fs::remove_dir_all(&feed);
    let mut p = Publisher::open_with(&feed, "n1", &root.verifying_key(), key, &cert_jws, cfg, authz_root.public())?;
    let mut r = Replica::new_with("n1", root.verifying_key(), ReplicaConfig::default(), authz_root.public());
    let t0 = now_ms();
    let tenant = TenantId::single().0;
    let not_after = (t0 / 1000 + 86_400) as u64;
    let issuer = Issuer::root(&authz_root, &tenant, "run:run_netbench", "run_netbench", 0, zone, &[], not_after, vec![approver.public()])?;
    p.commit(vec![Change::PutZone { zone: issuer.publish(&approver, &[])? }], t0)?;
    let hello = r.hello();
    for f in p.catch_up(&hello, t0)? {
        r.accept(&f, t0).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    }
    let replica = Arc::new(Mutex::new(r));
    tokio::spawn({
        let replica = replica.clone();
        async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let now = now_ms();
                let _ = replica.lock().unwrap().accept(&p.statement(now), now);
            }
        }
    });
    struct Connected;
    impl wicket_proxy::decide::ControlLink for Connected {
        fn connected(&self) -> bool {
            true
        }
        fn ask<'a>(
            &'a self,
            _: &'a wicket_core::Op,
            _: &'a str,
            _: Option<&'a serde_json::Value>,
        ) -> futures_util::future::BoxFuture<'a, Result<wicket_proxy::decide::Asked, String>> {
            Box::pin(async { Err("the bench never escalates".to_string()) })
        }
    }
    Ok(Arc::new(wicket_proxy::decide::NodeDecider { replica, clock: Arc::new(now_ms), control: Arc::new(Connected) }))
}
