//! A git push as one typed request (#26).
//!
//! A smart-HTTP push is two requests: ref discovery (`GET …/info/refs?service=git-receive-pack`),
//! then the upload (`POST …/git-receive-pack`). Both are decided as one op, the push of the
//! repository ([`push_op_path`]: `POST {repo}/git-receive-pack`), so they share one pending request
//! and one grant, and the zone, the token and the ledger all see the same op. A grant made for a
//! push covers both requests (and git's retries and probes) for a short window
//! ([`PUSH_WINDOW_SECS`]) rather than for a number of uses.
//!
//! wicket decides the push of a repository, not its refs: the request bodies are not read. Which
//! repositories and branches a push may update is the forge's to enforce, with the credential the
//! zone injects (a token scoped to the repositories the task needs) and its own branch rules
//! (GitHub rulesets or branch protection).
//!
//! Fetches are unaffected: `git-upload-pack` and its discovery stay reads (#179).

use crate::op::Op;

/// How long one approval of a push covers its requests (seconds), at most.
pub const PUSH_WINDOW_SECS: u64 = 300;

const DISCOVERY: &str = "/info/refs";
const RECEIVE_PACK: &str = "/git-receive-pack";

/// The repository a request pushes to, if it is one of a push's two requests: the ref discovery for
/// receive-pack (exactly `service=git-receive-pack`, as git sends it), or the receive-pack POST.
/// The repository is the path before `/info/refs` or `/git-receive-pack`, as written. Anything else
/// (a fetch, another query, an empty repository path) is None: decided as itself.
pub fn push_repo<'a>(method: &str, path: &'a str, query: &str) -> Option<&'a str> {
    let lower = path.to_ascii_lowercase();
    let repo = if method.eq_ignore_ascii_case("GET") && lower.ends_with(DISCOVERY) && query == "service=git-receive-pack" {
        &path[..path.len() - DISCOVERY.len()]
    } else if method.eq_ignore_ascii_case("POST") && lower.ends_with(RECEIVE_PACK) {
        &path[..path.len() - RECEIVE_PACK.len()]
    } else {
        return None;
    };
    (!repo.is_empty() && repo != "/").then_some(repo)
}

/// The path of the op a push to `repo` is decided as.
pub fn push_op_path(repo: &str) -> String {
    format!("{repo}{RECEIVE_PACK}")
}

/// The op a request is decided as: the push of its repository for either of a push's requests,
/// else the request itself. What the egress proxy decides, and so what an agent asking ahead
/// (`request_access`) must ask for, so its approval is the one the push finds.
pub fn op_for(tenant: &crate::TenantId, run: &crate::RunId, zone: &str, method: &str, host: &str, path: &str, query: &str) -> Op {
    match push_repo(method, path, query) {
        Some(repo) => Op::egress(tenant, run, zone, "POST", host, &push_op_path(repo)),
        None => Op::egress_with_query(tenant, run, zone, method, host, path, query),
    }
}

/// Whether an op (method and path) is a push's: what a grant for it covers for a window.
pub fn is_push(method: &str, path: &str) -> bool {
    method.eq_ignore_ascii_case("POST") && path.to_ascii_lowercase().ends_with(RECEIVE_PACK) && path.len() > RECEIVE_PACK.len() + 1
}

/// The uses and lifetime (seconds) a grant for `method path` is made with, given what the approver
/// picked: a push's grant covers its requests for [`PUSH_WINDOW_SECS`] at most, uncounted, since
/// one push is a discovery, an upload, and git's probes and retries between them. Others as picked.
pub fn grant_terms(method: &str, path: &str, uses: Option<u32>, ttl_secs: u64) -> (Option<u32>, u64) {
    if is_push(method, path) {
        (None, ttl_secs.min(PUSH_WINDOW_SECS))
    } else {
        (uses, ttl_secs)
    }
}

/// What a human is shown for a pending push: the repository, and that one approval covers the
/// push. Other ops: `why` unchanged.
pub fn ask_reason(op: &Op, why: &str) -> String {
    if !is_push(&op.method, &op.path) {
        return why.to_string();
    }
    let repo = &op.path[..op.path.len() - RECEIVE_PACK.len()];
    format!(
        "git push to {}{repo}: {why}; one approval covers this push's ref discovery and upload for {} minutes",
        op.host,
        PUSH_WINDOW_SECS / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_push_and_its_discovery_are_one_op_and_fetches_are_not() {
        assert_eq!(push_repo("GET", "/acme/app.git/info/refs", "service=git-receive-pack"), Some("/acme/app.git"));
        assert_eq!(push_repo("POST", "/acme/app.git/git-receive-pack", ""), Some("/acme/app.git"));
        assert_eq!(push_repo("POST", "/acme/App/GIT-RECEIVE-PACK", ""), Some("/acme/App"));
        // Fetches (#179), other queries and other methods are decided as themselves.
        assert_eq!(push_repo("GET", "/acme/app.git/info/refs", "service=git-upload-pack"), None);
        assert_eq!(push_repo("GET", "/acme/app.git/info/refs", ""), None);
        assert_eq!(push_repo("POST", "/acme/app.git/git-upload-pack", ""), None);
        assert_eq!(push_repo("GET", "/acme/app.git/info/refs", "service=git-receive-pack&x=1"), None);
        assert_eq!(push_repo("PUT", "/acme/app.git/git-receive-pack", ""), None);
        assert_eq!(push_repo("POST", "/git-receive-pack", ""), None);
        assert_eq!(push_op_path("/acme/app.git"), "/acme/app.git/git-receive-pack");
        assert!(is_push("POST", "/acme/app.git/git-receive-pack"));
        assert!(!is_push("GET", "/acme/app.git/git-receive-pack") && !is_push("POST", "/git-receive-pack"));
        let (t, r) = (crate::TenantId::single(), crate::RunId("r".into()));
        let d = op_for(&t, &r, "z", "GET", "github.com", "/acme/app.git/info/refs", "service=git-receive-pack");
        let u = op_for(&t, &r, "z", "POST", "github.com", "/acme/app.git/git-receive-pack", "");
        assert_eq!((d.method.as_str(), d.path.as_str(), d.digest()), ("POST", "/acme/app.git/git-receive-pack", u.digest()));
        assert_eq!(d.risk, crate::RiskClass::R4ExecOrPrivilege);
        let f = op_for(&t, &r, "z", "GET", "github.com", "/acme/app.git/info/refs", "service=git-upload-pack");
        assert_eq!((f.method.as_str(), f.risk), ("GET", crate::RiskClass::R1ReadScoped));
    }

    #[test]
    fn a_push_grant_is_a_window_and_others_are_as_picked() {
        assert_eq!(grant_terms("POST", "/acme/app.git/git-receive-pack", Some(1), 3600), (None, PUSH_WINDOW_SECS));
        assert_eq!(grant_terms("POST", "/acme/app.git/git-receive-pack", Some(1), 60), (None, 60));
        assert_eq!(grant_terms("POST", "/acme/app/issues", Some(1), 3600), (Some(1), 3600));
    }
}
