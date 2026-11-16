//! Windowed egress caps on the node (#368), end to end through the egress proxy: a zone with caps
//! sends nothing without a slice, a request past the slice is refused before it reaches the origin
//! (429), a declared body that doesn't fit is refused, a response body is cut where it passes the
//! slice, and a renewed slice lets requests through again.

use crate::zone_decider::ZoneDecider;
use bytes::Bytes;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use wicket_core::window::{EgressSlice, EgressUse};
use wicket_core::{RunId, TenantId, ZoneSpec};
use wicket_proxy::ca::RunCa;
use wicket_proxy::egress::caps::EgressCounter;
use wicket_proxy::egress::{Egress, Upstream};
use wicket_proxy::RunCtx;

const HOST: &str = "plain.test";

fn tmpdir() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("caps-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A plain-HTTP origin counting requests; `/big` answers 4 KiB with its length, `/stream` 4 KiB in
/// 512-byte chunks with none.
async fn origin(hits: Arc<AtomicUsize>) -> std::net::SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let hits = hits.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: http::Request<hyper::body::Incoming>| {
                    hits.fetch_add(1, Ordering::SeqCst);
                    async move {
                        use http_body_util::BodyExt;
                        type B = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;
                        let body: B = match req.uri().path() {
                            "/big" => http_body_util::Full::new(Bytes::from(vec![b'x'; 4096])).boxed(),
                            "/stream" => {
                                let chunks = (0..8)
                                    .map(|_| Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(Bytes::from(vec![b'x'; 512]))));
                                http_body_util::StreamBody::new(futures_util::stream::iter(chunks)).boxed()
                            }
                            _ => http_body_util::Full::new(Bytes::from_static(b"ok")).boxed(),
                        };
                        Ok::<_, hyper::Error>(http::Response::new(body))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(hyper_util::rt::TokioIo::new(s), svc).await;
            });
        }
    });
    addr
}

struct World {
    sock: PathBuf,
    hits: Arc<AtomicUsize>,
    counter: Arc<EgressCounter>,
    dir: PathBuf,
}

impl World {
    async fn new() -> World {
        let dir = tmpdir();
        let hits = Arc::new(AtomicUsize::new(0));
        let mut resolve = HashMap::new();
        resolve.insert(HOST.to_string(), origin(hits.clone()).await);
        let zone: ZoneSpec = serde_json::from_value(serde_json::json!({
            "name": "capped",
            "reach": [{ "host": HOST, "methods": ["GET", "POST"] }],
            "limits": { "egress": { "window": "1h", "requests": 100, "bytes": "1m" } },
        }))
        .unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut rx = rx;
            while rx.recv().await.is_some() {}
        });
        let caps = zone.limits.egress_caps().unwrap();
        let ctx = RunCtx {
            tenant: TenantId::single(),
            run: RunId("run_01jcaps0000000000000000000a".into()),
            zone: Arc::new(wicket_core::CompiledZone::new(zone).unwrap()),
            org: None,
            ledger: Arc::new(Mutex::new(wicket_store::Ledger::open_in_memory().unwrap())),
            vault: wicket_proxy::vault::Vault::new(dir.join("vault")),
            events: tx,
            escalate: false,
            attribute: None,
            identity: None,
            spawner: None,
            swaps: vec![],
            boxes: None,
            capacity: None,
            decisions: None,
            fence: None,
            waker: None,
            lifecycle: None,
        };
        let up = Upstream { resolve, ..Default::default() };
        let egress = Egress::with_upstream(ctx, Arc::new(RunCa::generate("run_caps").unwrap()), Arc::new(ZoneDecider), None, up).unwrap();
        let counter = EgressCounter::new(caps);
        egress.set_egress_counter(counter.clone());
        let sock = dir.join("egress.sock");
        let s2 = sock.clone();
        tokio::spawn(async move {
            if let Err(e) = egress.serve(&s2).await {
                eprintln!("serve: {e:#}");
            }
        });
        for _ in 0..3000 {
            if sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        World { sock, hits, counter, dir }
    }

    /// One plain-HTTP request; the whole answer as text.
    async fn call(&self, method: &str, path: &str, body: &str) -> String {
        let mut s = UnixStream::connect(&self.sock).await.unwrap();
        let len = if body.is_empty() { String::new() } else { format!("Content-Length: {}\r\n", body.len()) };
        s.write_all(format!("{method} http://{HOST}{path} HTTP/1.1\r\nHost: {HOST}\r\n{len}Connection: close\r\n\r\n{body}").as_bytes())
            .await
            .unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).into_owned()
    }
}

impl Drop for World {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_capped_zone_sends_only_what_its_slice_holds() {
    let w = World::new().await;
    // No slice yet: nothing goes.
    let a = w.call("GET", "/x", "").await;
    assert!(a.starts_with("HTTP/1.1 429") && a.contains("egress-cap") && a.contains("no egress allowance"), "{a}");
    assert_eq!(w.hits.load(Ordering::SeqCst), 0);
    // Two requests' worth: two go, the third is refused before the origin sees it.
    w.counter.set_slice(Some(EgressSlice { requests: Some(2), bytes: Some(1 << 20) }));
    for _ in 0..2 {
        let a = w.call("GET", "/x", "").await;
        assert!(a.starts_with("HTTP/1.1 200"), "{a}");
    }
    let a = w.call("GET", "/x", "").await;
    assert!(a.starts_with("HTTP/1.1 429") && a.contains("100 requests per 1h"), "{a}");
    assert_eq!(w.hits.load(Ordering::SeqCst), 2);
    assert_eq!(w.counter.used(), EgressUse { requests: 2, bytes: 4 }, "two answers of 2 bytes");
    // Renewed: requests go again; a declared body that doesn't fit is refused up front.
    w.counter.set_slice(Some(EgressSlice { requests: Some(10), bytes: Some(100) }));
    let a = w.call("POST", "/x", &"y".repeat(200)).await;
    assert!(a.starts_with("HTTP/1.1 429") && a.contains("doesn't fit"), "{a}");
    assert_eq!(w.hits.load(Ordering::SeqCst), 2);
    // An answer that says it won't fit is refused whole; one that doesn't say is cut where it
    // passes the slice: the box gets less than the origin sent, and never more than the slice.
    let a = w.call("GET", "/big", "").await;
    assert!(a.starts_with("HTTP/1.1 429") && a.contains("4096-byte body doesn't fit"), "{a}");
    let a = w.call("GET", "/stream", "").await;
    assert!(a.matches('x').count() < 4096, "the body was cut: {a:?}");
    assert!(w.counter.used().bytes <= 100, "{:?}", w.counter.used());
    // A slice no larger than what was counted (the control host had nothing more to lease):
    // refused again, and the origin saw only what was sent.
    w.counter.set_slice(Some(EgressSlice { requests: Some(w.counter.used().requests), bytes: None }));
    let a = w.call("GET", "/x", "").await;
    assert!(a.starts_with("HTTP/1.1 429"), "{a}");
    assert_eq!(w.hits.load(Ordering::SeqCst), 4);
}
