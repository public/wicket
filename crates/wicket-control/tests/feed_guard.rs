//! #796 review, H1: the guard a rollback below protocol 21 runs, over the node feeds in the data
//! directory: a node whose feed holds a box's record with host ports is named, one whose doesn't
//! isn't. Its own test binary: it sets the data directory. The feed files are written by hand (the
//! guard reads them as an older build would, without checking signatures).

use base64::Engine;
use wicket_control::noderun::{feeds_holding_ports, node_feed_holds_ports};

/// A delta log line (`header.payload.signature`) whose payload holds `change`.
fn line(epoch: u64, change: serde_json::Value) -> String {
    let b64 = |v: &serde_json::Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string());
    let payload = serde_json::json!({ "feed": "n", "version": 1, "epoch": epoch, "prev": "", "issued_at": 1, "changes": [change] });
    format!("{}.{}.c2ln", b64(&serde_json::json!({ "alg": "EdDSA" })), b64(&payload))
}

#[test]
fn the_guard_names_the_nodes_whose_feed_holds_ports() {
    let home = std::env::temp_dir().join(format!("wicket-feed-guard-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    // SAFETY: this test binary's only test, set before anything reads it.
    unsafe { std::env::set_var("WICKET_HOME", &home) };
    let data = wicket_home::data_dir();
    let feed = |node: &str, lines: &[String]| {
        let d = data.join("nodes").join(node).join("feed");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("deltas.jsonl"), lines.iter().map(|l| format!("{l}\n")).collect::<String>()).unwrap();
    };
    let port = serde_json::json!({ "name": "n-1", "label": "demo", "host_port": 20001, "box_port": 3000, "until_ms": 9 });
    let put = |ports: Vec<serde_json::Value>| serde_json::json!({ "op": "put_zone", "zone": { "run": "r", "ports": ports } });
    feed("plain", &[line(1, put(vec![]))]);
    feed("ported", &[line(1, put(vec![])), line(2, put(vec![port.clone()]))]);
    feed("revoked", &[line(1, serde_json::json!({ "op": "revoke", "kind": "run", "id": "r", "until": 1 }))]);
    assert_eq!(feeds_holding_ports().unwrap(), vec!["ported".to_string()]);
    assert!(node_feed_holds_ports("ported").unwrap());
    assert!(!node_feed_holds_ports("plain").unwrap());
    assert!(!node_feed_holds_ports("no-such-node").unwrap(), "a node without a feed holds nothing");
    let _ = std::fs::remove_dir_all(&home);
}
