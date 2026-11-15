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
