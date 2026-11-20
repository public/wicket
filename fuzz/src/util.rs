//! What the harnesses share: a run context for a zone, and a scratch directory on the volume the
//! fuzzer runs on (not /tmp, which is small in a box).

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// A directory for this process's scratch files: `$WICKET_FUZZ_TMP`, else the system's.
pub fn scratch(tag: &str) -> PathBuf {
    let base = std::env::var_os("WICKET_FUZZ_TMP").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let d = base.join(format!("wicket-fuzz-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch directory");
    d
}

/// A run context for a zone (YAML flow mapping body, e.g. `reach: [...]`), with an in-memory
/// ledger and an empty vault, and the receiving end of its events: the caller holds it for as long
/// as the context lives (forgetting it leaked the channel on every run, which LeakSanitizer reports).
/// Ignores SIGPIPE, once, as a Rust `main` would: libFuzzer's entry point doesn't, so a write to a
/// socket the other end closed killed the whole target (CI's egress run) instead of failing that write.
pub fn ignore_sigpipe() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    // SAFETY: setting SIGPIPE's disposition to SIG_IGN before any thread writes to a socket; the
    // handler is the libc constant, not code of ours.
    ONCE.call_once(|| unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    });
}

pub fn ctx(zone: &str, vault: PathBuf) -> (wicket_proxy::RunCtx, tokio::sync::mpsc::UnboundedReceiver<wicket_proxy::Event>) {
    ignore_sigpipe();
    let m =
        wicket_core::Manifest::from_yaml(&format!("task: t\nagent: {{name: a}}\nzone: {{name: z, {zone}}}")).expect("the harness's zone");
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let ctx = wicket_proxy::RunCtx {
        tenant: wicket_core::TenantId::single(),
        run: wicket_core::RunId("run_0123456789abcdefghijklmnop".into()),
        zone: Arc::new(wicket_core::CompiledZone::new(m.zone.clone()).expect("the harness's zone compiles")),
        org: None,
        ledger: Arc::new(Mutex::new(wicket_store::Ledger::open_in_memory().expect("ledger"))),
        vault: wicket_proxy::vault::Vault::new(vault),
        events: tx,
        escalate: false,
        attribute: None,
        identity: None,
        swaps: vec![],
        boxes: None,
        capacity: None,
        decisions: None,
        fence: None,
        waker: None,
        lifecycle: None,
        names: None,
    };
    (ctx, rx)
}
