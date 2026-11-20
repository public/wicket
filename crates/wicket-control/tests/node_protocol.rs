//! #682 re-review: a zone that decides an encoded slash (`decode_slash`, #664) is refused for a
//! node not known to read its record (protocol 19), before anything goes in the node's feed, which
//! every session to the node carries: an 18 node's strict parse would refuse the record and stall
//! its whole feed, its other boxes' included. Its own test binary: it sets the data directory.

use wicket_control::noderun::{check_protocol, feed_config, known_protocol, note_protocol, protocol_needed, SharedFeed};
use wicket_feed::{Change, RevokeKind};

fn zone(rule: &str) -> wicket_core::ZoneSpec {
    wicket_core::yaml::from_str(&format!("name: z\nreach:\n  - {rule}\n")).unwrap()
}

fn revoke(id: &str) -> Change<wicket_feed::BoxAuthority> {
    Change::Revoke { kind: RevokeKind::Run, id: id.into(), until: wicket_feed::now_ms() + 3_600_000 }
}

#[test]
fn a_decoding_zone_is_never_published_to_a_node_that_cant_read_it() {
    let home = std::env::temp_dir().join(format!("wicket-node-protocol-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    // SAFETY: this test binary's only test, set before anything reads it.
    unsafe { std::env::set_var("WICKET_HOME", &home) };

    let plain = zone("{ host: registry.npmjs.org, methods: [GET], paths: [\"/**\"] }");
    let decoding = zone("{ host: registry.npmjs.org, methods: [GET], paths: [\"/**\"], decode_slash: [1] }");
    assert_eq!(protocol_needed(&plain), 0);
    assert_eq!(protocol_needed(&decoding), wicket_chan::chan::DECODE_SLASH);

    // A node never connected: its protocol isn't known, so nothing that needs 19 goes to it.
    assert_eq!(known_protocol("old"), None);
    let e = check_protocol("old", &decoding).unwrap_err().to_string();
    assert!(e.contains("isn't known"), "{e}");
    check_protocol("old", &plain).unwrap();

    // A node at 18 with a plain box on it: its feed carries that box's changes.
    note_protocol("old", 18);
    assert_eq!(known_protocol("old"), Some(18));
    let feed = SharedFeed::open("old", feed_config()).unwrap();
    check_protocol("old", &plain).unwrap();
    feed.lock().unwrap().commit(vec![revoke("run_plain_1")], wicket_feed::now_ms()).unwrap();
    let before = feed.lock().unwrap().epoch();
    // The decoding zone is refused there, before `start` mints or publishes anything.
    let e = check_protocol("old", &decoding).unwrap_err().to_string();
    assert!(e.contains("node old talks 18") && e.contains("decode_slash") && e.contains("wicket self update --nodes"), "{e}");
    assert_eq!(feed.lock().unwrap().epoch(), before, "nothing went in the feed");
    // The plain box's feed goes on.
    feed.lock().unwrap().commit(vec![revoke("run_plain_2")], wicket_feed::now_ms()).unwrap();
    assert_eq!(feed.lock().unwrap().epoch(), before + 1);

    // Once the node talks 19 (a connection's welcome notes it), the zone may go there.
    note_protocol("old", wicket_chan::chan::DECODE_SLASH);
    check_protocol("old", &decoding).unwrap();
    let _ = std::fs::remove_dir_all(&home);
}
