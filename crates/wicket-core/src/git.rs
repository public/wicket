//! A git push as one typed request (#26).
//!
//! A smart-HTTP push is two requests: ref discovery (`GET …/info/refs?service=git-receive-pack`),
//! then the upload (`POST …/git-receive-pack`, whose body starts with the ref update commands). Both
//! are decided as one op, the push of the repository ([`push_op_path`]: `POST {repo}/git-receive-pack`),
//! so they share one pending request and one grant, and the zone, the token and the ledger all see
//! the same op. A grant made for a push covers both requests (and git's retries and probes) for a
//! short window ([`PUSH_WINDOW_SECS`]) rather than for a number of uses.
//!
//! The refs a push updates are read from the receive-pack commands ([`commands`]). Each is checked
//! before the push is decided or asked about: a ref git itself would refuse, one the forge never
//! accepts a push to ([`forge_refuses`]), and one a zone or org forbid rule covers are refused
//! outright. A forbid rule names a protected ref by its *ref path* ([`ref_paths`]),
//! `{repo}/git-receive-pack/{ref}`: for example
//! `{ host: github.com, paths: ["/acme/app.git/git-receive-pack/refs/heads/main"] }`, or
//! `"/**/git-receive-pack/refs/heads/main"` for every repository on the host. A ref path is only
//! ever checked against forbid rules (it is never forwarded, granted or asked about), so the zone
//! and the box's token decide it alike, on the node as on the control host.
//!
//! Fetches are unaffected: `git-upload-pack` and its discovery stay reads (#179).

use crate::op::Op;

/// How long one approval of a push covers its requests (seconds), at most.
pub const PUSH_WINDOW_SECS: u64 = 300;

/// The most bytes of a receive-pack body read for its commands, before the pack data.
pub const MAX_COMMANDS_BYTES: usize = 1024 * 1024;

/// The effect an op carries naming the refs of a push (for the human's card).
pub const REFS_EFFECT: &str = "git.refs: ";

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

/// Whether an op (method and path) is a push's: what a grant for it covers for a window.
pub fn is_push(method: &str, path: &str) -> bool {
    method.eq_ignore_ascii_case("POST") && path.to_ascii_lowercase().ends_with(RECEIVE_PACK) && path.len() > RECEIVE_PACK.len() + 1
}

/// The paths a ref update of `repo` is checked against forbid rules as: with and without `.git`
/// (forges serve both spellings of a repository), so one rule covers either.
pub fn ref_paths(repo: &str, name: &str) -> Vec<String> {
    let bare = repo.strip_suffix(".git").or_else(|| repo.strip_suffix(".GIT")).unwrap_or(repo);
    let mut v = vec![format!("{bare}.git{RECEIVE_PACK}/{name}"), format!("{bare}{RECEIVE_PACK}/{name}")];
    v.dedup();
    v
}

/// One ref update command of a push.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefUpdate {
    pub old: String,
    pub new: String,
    pub name: String,
}

impl RefUpdate {
    pub fn is_delete(&self) -> bool {
        self.new.bytes().all(|b| b == b'0')
    }
}

fn is_oid(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The ref update commands at the start of a receive-pack body (pkt-lines up to the first flush):
/// `Ok(None)` if `buf` doesn't hold them all yet, an error if they can't be read (a malformed
/// pkt-line, an unexpected line, more than [`MAX_COMMANDS_BYTES`]). `shallow` lines are skipped; a
/// push certificate's own lines are skipped and the commands inside it read.
pub fn commands(buf: &[u8]) -> Result<Option<Vec<RefUpdate>>, String> {
    let mut out = Vec::new();
    let mut at = 0;
    let mut cert = false;
    loop {
        if at + 4 > buf.len() {
            return if buf.len() > MAX_COMMANDS_BYTES { Err(too_long()) } else { Ok(None) };
        }
        let len = std::str::from_utf8(&buf[at..at + 4])
            .ok()
            .and_then(|h| usize::from_str_radix(h, 16).ok())
            .filter(|_| buf[at..at + 4].iter().all(u8::is_ascii_hexdigit))
            .ok_or("the push's commands are not pkt-lines")?;
        if len == 0 {
            return Ok(Some(out));
        }
        if len < 4 {
            return Err(format!("unexpected pkt-line {len:04x} in the push's commands"));
        }
        if at + len > MAX_COMMANDS_BYTES {
            return Err(too_long());
        }
        if at + len > buf.len() {
            return Ok(None);
        }
        let line = &buf[at + 4..at + len];
        at += len;
        // Capabilities follow a NUL on the first line.
        let line = line.split(|&b| b == 0).next().unwrap_or_default();
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        let line = std::str::from_utf8(line).map_err(|_| "a command of the push is not UTF-8".to_string())?;
        if out.is_empty() && !cert && line == "push-cert" {
            cert = true;
            continue;
        }
        if cert && line == "push-cert-end" {
            cert = false;
            continue;
        }
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        match parts[..] {
            [old, new, name] if is_oid(old) && is_oid(new) && old.len() == new.len() => {
                out.push(RefUpdate { old: old.into(), new: new.into(), name: name.into() });
            }
            ["shallow", oid] if is_oid(oid) => {}
            _ if cert => {}
            _ => return Err(format!("unexpected line in the push's commands: {:?}", crate::text::clip(line, 80))),
        }
    }
}

fn too_long() -> String {
    format!("the push's commands are longer than {MAX_COMMANDS_BYTES} bytes")
}

/// Why git itself would refuse `name` as a ref to push to (`git check-ref-format`, and under
/// `refs/`), if it would. Checked so a ref path can't be spelled to dodge a forbid glob.
pub fn bad_ref_name(name: &str) -> Option<String> {
    let bad = |why: &str| Some(format!("{:?} is not a valid ref name ({why})", crate::text::clip(name, 80)));
    if !name.starts_with("refs/") || name.len() > 1024 {
        return bad("a push updates refs under refs/");
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7f || b" ~^:?*[\\".contains(&b)) {
        return bad("a control character, space or one of ~^:?*[\\");
    }
    if name.contains("..") || name.contains("@{") || name.ends_with('/') || name.ends_with('.') {
        return bad("'..', '@{', or a trailing '/' or '.'");
    }
    if name.split('/').any(|c| c.is_empty() || c.starts_with('.') || c.ends_with(".lock")) {
        return bad("an empty component, or one starting with '.' or ending in '.lock'");
    }
    None
}

/// Why the forge refuses every push to `name` on `host`, by rules wicket knows, if it does: GitHub's
/// pull request refs (`refs/pull/…`) are read-only.
pub fn forge_refuses(host: &str, name: &str) -> Option<String> {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "github.com" && name.starts_with("refs/pull/") {
        return Some(format!("{name} is one of GitHub's pull request refs, which are read-only"));
    }
    None
}

/// What a human is shown for a pending push: the repository, the refs where they were read, and
/// that one approval covers the push. Other ops: `why` unchanged.
pub fn ask_reason(op: &Op, why: &str) -> String {
    if !is_push(&op.method, &op.path) {
        return why.to_string();
    }
    let repo = &op.path[..op.path.len() - RECEIVE_PACK.len()];
    let refs = op.effects.iter().find_map(|e| e.strip_prefix(REFS_EFFECT)).map(|r| format!(" ({r})")).unwrap_or_default();
    format!(
        "git push to {}{repo}{refs}: {why}; one approval covers this push's ref discovery and upload for {} minutes",
        op.host,
        PUSH_WINDOW_SECS / 60
    )
}

/// The effect naming a push's refs (shown, never decided on).
pub fn refs_effect(updates: &[RefUpdate]) -> Option<String> {
    if updates.is_empty() {
        return None;
    }
    let names: Vec<&str> = updates.iter().map(|u| u.name.as_str()).collect();
    Some(format!("{REFS_EFFECT}{}", crate::text::clip(&names.join(", "), 200)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(s: &str) -> Vec<u8> {
        let mut v = format!("{:04x}", s.len() + 4).into_bytes();
        v.extend_from_slice(s.as_bytes());
        v
    }

    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";
    const Z: &str = "0000000000000000000000000000000000000000";

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
        assert_eq!(
            ref_paths("/acme/app", "refs/heads/main"),
            ["/acme/app.git/git-receive-pack/refs/heads/main", "/acme/app/git-receive-pack/refs/heads/main"]
        );
        assert_eq!(ref_paths("/acme/app.git", "refs/heads/main"), ref_paths("/acme/app", "refs/heads/main"));
    }

    #[test]
    fn commands_are_read_up_to_the_flush() {
        let mut body = pkt(&format!("{A} {B} refs/heads/main\0report-status side-band-64k\n"));
        body.extend(pkt(&format!("{Z} {B} refs/heads/feat\n")));
        body.extend(pkt(&format!("{A} {Z} refs/tags/old\n")));
        // Every prefix short of the flush needs more bytes.
        for n in 0..body.len() + 3 {
            let mut b = body.clone();
            b.extend(b"0000PACK");
            assert_eq!(commands(&b[..n]), Ok(None), "{n}");
        }
        body.extend(b"0000PACK\x00\x00\x00\x02");
        let c = commands(&body).unwrap().unwrap();
        assert_eq!(c.iter().map(|u| u.name.as_str()).collect::<Vec<_>>(), ["refs/heads/main", "refs/heads/feat", "refs/tags/old"]);
        assert!(c[2].is_delete() && !c[0].is_delete());
        // git's probe for a large push: a lone flush.
        assert_eq!(commands(b"0000"), Ok(Some(vec![])));
        // Shallow lines are skipped; a push certificate's commands are read.
        let mut s = pkt(&format!("shallow {A}"));
        s.extend(pkt(&format!("{A} {B} refs/heads/x\n")));
        s.extend(b"0000");
        assert_eq!(commands(&s).unwrap().unwrap().len(), 1);
        let mut cert = pkt("push-cert\0report-status\n");
        for l in ["certificate version 0.1\n", "pusher x 1 +0000\n", "\n", &format!("{A} {B} refs/heads/y\n"), "-----BEGIN PGP SIGNATURE-----\n", "push-cert-end\n"] {
            cert.extend(pkt(l));
        }
        cert.extend(b"0000");
        assert_eq!(commands(&cert).unwrap().unwrap()[0].name, "refs/heads/y");
        // Unreadable: refused, never guessed.
        assert!(commands(b"zzzz").is_err());
        assert!(commands(b"0002").is_err());
        assert!(commands(&[pkt("hello\n"), b"0000".to_vec()].concat()).is_err());
        assert_eq!(commands(b"0000garbage"), Ok(Some(vec![])), "what follows the flush is the pack");
        let huge: Vec<u8> = std::iter::repeat_n(pkt(&format!("shallow {A}")), MAX_COMMANDS_BYTES / 40).flatten().collect();
        assert!(commands(&huge).is_err());
    }

    #[test]
    fn ref_names_are_checked_as_git_does() {
        for ok in ["refs/heads/main", "refs/heads/feat/x-1", "refs/tags/v1.0", "refs/heads/caf\u{e9}"] {
            assert_eq!(bad_ref_name(ok), None, "{ok}");
        }
        for bad in [
            "main",
            "refs/heads/../main",
            "refs/heads//main",
            "refs/heads/main/",
            "refs/heads/.hidden",
            "refs/heads/main.lock",
            "refs/heads/a b",
            "refs/heads/a*",
            "refs/heads/a@{1}",
            "refs/heads/main.",
            "refs/heads/a\u{7f}",
        ] {
            assert!(bad_ref_name(bad).is_some(), "{bad}");
        }
        assert!(forge_refuses("github.com", "refs/pull/1/head").is_some());
        assert!(forge_refuses("GitHub.com.", "refs/pull/1/merge").is_some());
        assert_eq!(forge_refuses("github.com", "refs/heads/pull"), None);
        assert_eq!(forge_refuses("gitlab.example", "refs/pull/1/head"), None);
    }
}
