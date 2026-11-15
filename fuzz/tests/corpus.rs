//! Replays every seed (`corpus/<target>/`) and every past finding (`regressions/<target>/`)
//! through the harnesses, on the stable toolchain: `cargo test` in `fuzz/`.

use std::path::Path;

fn replay(target: &str, run: fn(&[u8])) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut n = 0;
    for dir in ["corpus", "regressions"] {
        let Ok(rd) = std::fs::read_dir(root.join(dir).join(target)) else { continue };
        let mut files: Vec<_> = rd.map(|e| e.unwrap().path()).collect();
        files.sort();
        for f in files {
            let data = std::fs::read(&f).unwrap();
            if let Err(e) = std::panic::catch_unwind(|| run(&data)) {
                std::panic::resume_unwind(Box::new(format!("{}: {:?}", f.display(), e.downcast_ref::<String>())));
            }
            n += 1;
        }
    }
    assert!(n > 0, "no inputs for {target}");
}

#[test]
fn egress() {
    replay("egress", wicket_fuzz::egress::run);
}
#[test]
fn gateway() {
    replay("gateway", wicket_fuzz::gateway::run);
}
#[test]
fn chan() {
    replay("chan", wicket_fuzz::node_chan::run);
}
#[test]
fn feed() {
    replay("feed", wicket_fuzz::feed::run);
}
#[test]
fn token() {
    replay("token", wicket_fuzz::token::run);
}
#[test]
fn manifest() {
    replay("manifest", wicket_fuzz::manifest::run);
}
#[test]
fn store() {
    replay("store", wicket_fuzz::store::run);
}
#[test]
fn git() {
    replay("git", wicket_fuzz::git::run);
}

/// The egress oracle is only as good as its view of the origins: allowed requests get there.
#[test]
fn egress_requests_reach_the_origins() {
    let (d, u) = wicket_fuzz::egress::exchange(b"\x01GET /a HTTP/1.1\r\nhost: fuzz.example\r\n\r\nPOST /b HTTP/1.1\r\ncontent-length: 2\r\n\r\nhi");
    assert_eq!(d.len(), 2, "{d:?}");
    assert_eq!(u.len(), 2, "{u:?}");
    assert_eq!((u[1].method.as_str(), u[1].host.as_str(), u[1].path.as_str()), ("POST", "fuzz.example", "/b"));
    let (d, u) = wicket_fuzz::egress::exchange(b"\x00GET http://plain.example/x?y HTTP/1.1\r\n\r\n");
    assert_eq!((d.len(), u.len()), (1, 1), "{d:?} {u:?}");
    assert_eq!(u[0].path, "/x?y");
    // A hidden request in a body is decided as nothing and reaches nobody.
    let (_, u) = wicket_fuzz::egress::exchange(b"\x00CONNECT other.example:443 HTTP/1.1\r\n\r\n");
    assert!(u.is_empty());
}
