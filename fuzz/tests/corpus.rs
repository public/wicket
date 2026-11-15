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
    let (d, u) =
        wicket_fuzz::egress::exchange(b"\x01GET /a HTTP/1.1\r\nhost: fuzz.example\r\n\r\nPOST /b HTTP/1.1\r\ncontent-length: 2\r\n\r\nhi");
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

/// A request the proxy forwards after the box's connection ended reaches the origin during the
/// next run (fuzzing found it as `regressions/egress/late-upstream-after-http01`, whose own bytes
/// decide nothing): it matches the earlier run's decision, and a request nobody decided still fails.
#[test]
fn egress_late_requests_match_earlier_decisions() {
    use wicket_fuzz::egress::{check_with, Seen};
    let post = Seen { method: "POST".into(), host: "fuzz.example".into(), path: "/a".into() };
    let get = Seen { method: "GET".into(), host: "fuzz.example".into(), path: "/b".into() };
    // Run 1 decides POST /a; nothing reaches the origin in time.
    let late = check_with(vec![], std::slice::from_ref(&post), &[]);
    assert_eq!(late, vec![post.clone()]);
    // Run 2 decides GET /b; the origin gets GET /b, then the late POST /a.
    assert!(check_with(late, std::slice::from_ref(&get), &[get.clone(), post.clone()]).is_empty());
    // Run 2 also decides POST /a itself, and the late POST /a matches that decision first: the
    // earlier one is still carried, for run 2's own POST /a arriving in run 3.
    let late = check_with(vec![post.clone()], std::slice::from_ref(&post), std::slice::from_ref(&post));
    assert_eq!(late, vec![post.clone()]);
    assert!(check_with(late, &[], std::slice::from_ref(&post)).is_empty());
    // Without the earlier decision, the same POST /a is smuggled.
    let smuggled = std::panic::catch_unwind(|| check_with(vec![], std::slice::from_ref(&get), &[get.clone(), post.clone()]));
    assert!(smuggled.is_err());
}
