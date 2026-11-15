//! Target 6: git push, as the egress proxy decides it (`wicket_core::git`). wicket doesn't read a
//! push's pkt-lines (the request bodies aren't parsed: which refs a push updates is the forge's to
//! enforce, see `git.rs`), so what a box controls is the method, path and query of the push's two
//! requests. The input is `METHOD path[?query]`; the path is canonicalised first, as the proxy does.
//! (The egress target sends whole pushes, pkt-lines and all, through the proxy.)
//!
//! The oracle: no panic; a request taken as a push is decided as the push of its repository, the
//! same op for its discovery and its upload, and that op is a push (its grant covers a window, not
//! a count); and an op that isn't a push keeps its grant's uses and lifetime.

use wicket_core::git::{grant_terms, is_push, op_for, push_op_path, push_repo, PUSH_WINDOW_SECS};
use wicket_core::{RunId, TenantId};

pub fn run(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let Some((method, target)) = text.split_once(' ') else { return };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let Ok(canon) = wicket_core::canonical_path(path) else { return };
    let path = canon.to_string();
    let (t, r) = (TenantId::single(), RunId("run_a".into()));
    let op = op_for(&t, &r, "z", method, "github.com", &path, query);
    let (uses, ttl) = grant_terms(&op.method, &op.path, Some(3), 3600);
    if is_push(&op.method, &op.path) {
        assert_eq!((uses, ttl), (None, PUSH_WINDOW_SECS));
    } else {
        assert_eq!((uses, ttl), (Some(3), 3600));
    }
    if let Some(repo) = push_repo(method, &path, query) {
        assert!(is_push(&op.method, &op.path), "{method} {path}?{query} is decided as push {:?}, which isn't a push", op.path);
        assert_eq!(op.path, push_op_path(repo));
        let discovery = op_for(&t, &r, "z", "GET", "github.com", &format!("{repo}/info/refs"), "service=git-receive-pack");
        let upload = op_for(&t, &r, "z", "POST", "github.com", &format!("{repo}/git-receive-pack"), "");
        assert_eq!((&discovery.method, &discovery.path), (&upload.method, &upload.path));
        assert_eq!((&op.method, &op.path), (&upload.method, &upload.path));
        assert_eq!(discovery.digest(), upload.digest(), "a push's two requests are two ops");
    }
}
