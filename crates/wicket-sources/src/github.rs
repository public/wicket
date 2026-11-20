//! GitHub's webhooks: `X-Hub-Signature-256` over the raw body, `X-GitHub-Event` and
//! `X-GitHub-Delivery`, a repository, and a fixed list of fields per event.
//!
//! GitHub signs neither its delivery id nor a time, nor the event header: a delivery's dedup is
//! keyed on its body, and its body must be the event it says it is ([`github_body_is`]).

use crate::{Adapter, Header, Hook, Signed, Unfit};
use serde_json::{Map, Value};
use std::borrow::Cow;
use wicket_core::intake::{self as ik, keep_text, IntakeTrigger};
use wicket_core::trigger::Source;

/// A GitHub field's text: at most this many bytes.
pub const MAX_GITHUB_TEXT: usize = 256;
/// A GitHub delivery's labels: at most this many.
pub const MAX_LABELS: usize = 20;
/// GitHub's signature header (`sha256=<hex>` of the HMAC-SHA256 of the raw body).
pub const GITHUB_SIGNATURE: &str = "x-hub-signature-256";
/// GitHub's event and delivery headers.
pub const GITHUB_EVENT: &str = "x-github-event";
pub const GITHUB_DELIVERY: &str = "x-github-delivery";
/// Its kind (the ledger's event source).
pub const KIND: &str = "github";

/// The object a GitHub event's payload must carry to be that event (#714 review B): the event
/// header isn't signed, so a signed body of one event can't be resent as another.
pub fn github_event_object(event: &str) -> Option<&'static str> {
    Some(match event {
        "pull_request" | "pull_request_review" | "pull_request_review_comment" => "/pull_request",
        "issues" | "issue_comment" => "/issue",
        "check_suite" => "/check_suite",
        "check_run" => "/check_run",
        "workflow_run" => "/workflow_run",
        "push" => "/ref",
        // Not listened to yet (not in `GITHUB_EVENTS`), but told apart from its status already.
        "deployment" => "/deployment",
        _ => return None,
    })
}

/// Whether `body` is a payload of GitHub `event`: it has that event's own object (and, for a
/// review or a comment, theirs too).
pub fn github_body_is(event: &str, body: &Value) -> bool {
    let Some(p) = github_event_object(event) else { return false };
    let has = |q: &str| body.pointer(q).is_some_and(|v| !v.is_null());
    // Each event's own objects, and none of a sibling event's: a review's or a comment's body isn't
    // the pull request's or the issue's, and only a push has `after` with its commits or pusher
    // (#714 fourth review, B).
    // A review thread's body (`pull_request_review_thread`) has the pull request and a `thread`; a
    // deployment's or its status's has a `deployment`, and may carry a check run or workflow run
    // (#714 fifth review).
    let fits = match event {
        "pull_request" => !has("/review") && !has("/comment") && !has("/thread"),
        "pull_request_review" => has("/review") && !has("/comment") && !has("/thread"),
        "pull_request_review_comment" => has("/comment") && !has("/review") && !has("/thread"),
        "issues" => !has("/comment"),
        "issue_comment" => has("/comment"),
        "push" => has("/after") && (has("/commits") || has("/pusher")),
        "check_suite" | "check_run" | "workflow_run" => !has("/deployment") && !has("/deployment_status"),
        "deployment" => !has("/deployment_status"),
        _ => true,
    };
    has(p) && fits
}

/// What a GitHub delivery's body says about where it came from, before the trigger's own check:
/// the repository's `full_name`, if it has one.
pub fn github_repo(body: &Value) -> Option<String> {
    body.pointer("/repository/full_name").and_then(Value::as_str).map(|s| keep_text(s, MAX_GITHUB_TEXT))
}

/// A GitHub delivery's fields (`event` is its `X-GitHub-Event`): a fixed list, each string cut at
/// [`MAX_GITHUB_TEXT`] and stripped, labels joined with `,` (at most [`MAX_LABELS`]). Fields a
/// delivery hasn't are left out.
///
/// - every event: `event`, `action`, `repo`, `sender`;
/// - `pull_request`, `pull_request_review`, `pull_request_review_comment`: `pr.number`,
///   `pr.author`, `pr.title`, `pr.url`, `pr.draft`, `branch` (its head), `head_repo`, `base`,
///   `labels`, and for a review `review.state`;
/// - `issues`, `issue_comment`: `issue.number`, `issue.author`, `issue.title`, `issue.url`,
///   `labels`, `comment.author` and `comment.url` (a comment), and `pr.number` when the issue is a
///   pull request;
/// - `check_suite`, `check_run`: `check.name`, `check.status`, `check.conclusion`, `check.url`,
///   `branch`, `sha`, and `pr.number` for the first pull request it belongs to;
/// - `workflow_run`: `check.name`, `check.status`, `check.conclusion`, `check.url`, `branch`,
///   `sha`, `pr.number`;
/// - `push`: `branch` (a branch's ref without its one `refs/heads/`; none for a tag), `ref`, `sha`
///   (after), `pusher`;
/// - and `fork` on every event: whether `head_repo` (a pull request's or workflow run's head
///   repository) is another repository than `repo`, or, for a pull request event, that its head
///   repository is gone (a deleted fork). A check suite or run, an issue comment or a push doesn't
///   say (GitHub lists no pull request on a check from a fork): `fork` is false there, so don't rely
///   on `branch` alone to mean the repository's own branch.
pub fn github_fields(event: &str, body: &Value) -> Value {
    let mut f = Map::new();
    let s = |p: &str| body.pointer(p).and_then(Value::as_str).map(|v| Value::String(keep_text(v, MAX_GITHUB_TEXT)));
    let n = |p: &str| body.pointer(p).and_then(Value::as_i64).map(Value::from);
    let b = |p: &str| body.pointer(p).and_then(Value::as_bool).map(Value::Bool);
    // Labels joined with `,`, whole labels only, within MAX_GITHUB_TEXT: a long list keeps its
    // first ones rather than making the event too big to keep (#714 review M6).
    let labels = |p: &str| {
        body.pointer(p).and_then(Value::as_array).map(|ls| {
            let mut out = String::new();
            for l in ls.iter().filter_map(|l| l["name"].as_str()).take(MAX_LABELS) {
                let l = keep_text(l, 64).replace(',', " ");
                if out.len() + l.len() + 1 > MAX_GITHUB_TEXT {
                    break;
                }
                if !out.is_empty() {
                    out.push(',');
                }
                out.push_str(&l);
            }
            Value::String(out)
        })
    };
    let mut put = |path: &str, v: Option<Value>| {
        let Some(v) = v else { return };
        let mut parts: Vec<&str> = path.split('.').collect();
        let last = parts.pop().expect("a path");
        let mut m = &mut f;
        for p in parts {
            m = m.entry(p).or_insert_with(|| Value::Object(Map::new())).as_object_mut().expect("an object");
        }
        m.insert(last.to_string(), v);
    };
    put("event", Some(Value::String(keep_text(event, 64))));
    put("action", s("/action"));
    put("repo", s("/repository/full_name"));
    put("sender", s("/sender/login"));
    match event {
        "pull_request" | "pull_request_review" | "pull_request_review_comment" => {
            put("pr.number", n("/pull_request/number"));
            put("pr.author", s("/pull_request/user/login"));
            put("pr.title", s("/pull_request/title"));
            put("pr.url", s("/pull_request/html_url"));
            put("pr.draft", b("/pull_request/draft"));
            put("branch", s("/pull_request/head/ref"));
            put("base", s("/pull_request/base/ref"));
            // A fork's PR names its own branch (often `main`): the branch alone says nothing about
            // the repository's (#714 review M5).
            put("head_repo", s("/pull_request/head/repo/full_name"));
            put("labels", labels("/pull_request/labels"));
            put("review.state", s("/review/state"));
            put("comment.author", s("/comment/user/login"));
            put("comment.url", s("/comment/html_url"));
        }
        "issues" | "issue_comment" => {
            put("issue.number", n("/issue/number"));
            put("issue.author", s("/issue/user/login"));
            put("issue.title", s("/issue/title"));
            put("issue.url", s("/issue/html_url"));
            put("labels", labels("/issue/labels"));
            put("comment.author", s("/comment/user/login"));
            put("comment.url", s("/comment/html_url"));
            if body.pointer("/issue/pull_request").is_some() {
                put("pr.number", n("/issue/number"));
            }
        }
        "check_suite" | "check_run" => {
            let o = if event == "check_suite" { "/check_suite" } else { "/check_run" };
            put("check.name", s(&format!("{o}/name")).or_else(|| s(&format!("{o}/app/name"))));
            put("check.status", s(&format!("{o}/status")));
            put("check.conclusion", s(&format!("{o}/conclusion")));
            put("check.url", s(&format!("{o}/html_url")).or_else(|| s(&format!("{o}/url"))));
            put("branch", s(&format!("{o}/head_branch")).or_else(|| s("/check_run/check_suite/head_branch")));
            put("sha", s(&format!("{o}/head_sha")));
            put("pr.number", n(&format!("{o}/pull_requests/0/number")));
        }
        "workflow_run" => {
            put("check.name", s("/workflow_run/name"));
            put("check.status", s("/workflow_run/status"));
            put("check.conclusion", s("/workflow_run/conclusion"));
            put("check.url", s("/workflow_run/html_url"));
            put("branch", s("/workflow_run/head_branch"));
            put("sha", s("/workflow_run/head_sha"));
            put("pr.number", n("/workflow_run/pull_requests/0/number"));
            put("head_repo", s("/workflow_run/head_repository/full_name"));
        }
        "push" => {
            // Only the one prefix: a branch named `refs/heads/main` stays itself (#714 review M5);
            // a tag's push isn't a branch.
            put(
                "branch",
                s("/ref").and_then(|v| v.as_str().and_then(|r| r.strip_prefix("refs/heads/")).map(|b| Value::String(b.to_string()))),
            );
            put("ref", s("/ref"));
            put("sha", s("/after"));
            put("pusher", s("/pusher/name"));
        }
        _ => {}
    }
    // `fork`: the change comes from another repository than the one the trigger listens to. A pull
    // request whose head repository is gone (a deleted fork: GitHub sends null) counts as a fork
    // (#714 review F6); events that don't say (a check, a comment) read false.
    let pr_event = matches!(event, "pull_request" | "pull_request_review" | "pull_request_review_comment");
    let fork = match (f.get("head_repo").and_then(Value::as_str), f.get("repo").and_then(Value::as_str)) {
        (Some(h), Some(r)) => !h.eq_ignore_ascii_case(r),
        (None, _) if pr_event && body.pointer("/pull_request").is_some() => true,
        _ => false,
    };
    f.insert("fork".into(), Value::Bool(fork));
    Value::Object(f)
}

/// GitHub's adapter.
pub struct Github;

impl Adapter for Github {
    fn kind(&self) -> &'static str {
        KIND
    }

    fn hook<'a>(&self, source: &'a Source) -> Option<Hook<'a>> {
        match source {
            Source::Github { repo, events, verify } => {
                Some(Hook { kind: KIND, verify: &verify.hmac_sha256, repo: Some(repo.clone()), events: events.clone() })
            }
            _ => None,
        }
    }

    fn verify<'b>(&self, secret: &[u8], header: Header<'_>, body: &'b [u8], _: i64) -> Option<Signed<'b>> {
        // GitHub's id and time aren't signed: its dedup is keyed on its body.
        ik::signature_ok(secret, body, header(GITHUB_SIGNATURE).as_deref())
            .then(|| Signed { delivery: header(GITHUB_DELIVERY), message: Cow::Borrowed(body) })
    }

    fn normalise(&self, t: &IntakeTrigger, header: Header<'_>, body: &[u8]) -> Result<(String, Value), Unfit> {
        let event = header(GITHUB_EVENT).unwrap_or_default();
        let Ok(v) = serde_json::from_slice::<Value>(body) else { return Err(Unfit::Malformed("not json")) };
        if !t.events.contains(&event) {
            return Err(Unfit::NotListened("not listened to"));
        }
        // The event header isn't signed: the body must be that event's (#714 review B).
        if !github_body_is(&event, &v) {
            return Err(Unfit::Refused("not that event"));
        }
        // GitHub's repository names ignore case.
        match (github_repo(&v), t.repo.as_deref()) {
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => {}
            _ => return Err(Unfit::Refused("another repository")),
        }
        let fields = github_fields(&event, &v);
        Ok((event, fields))
    }

    fn listens(&self, hook: &Hook<'_>, kind: &str) -> bool {
        hook.events.iter().any(|e| e == kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_core::intake::fields_within;

    /// #714 review B: a signed body is the event it says only if it has that event's object.
    #[test]
    fn a_body_is_only_its_own_event() {
        let issue = serde_json::json!({ "action": "opened", "issue": { "number": 1 }, "repository": { "full_name": "a/b" } });
        assert!(github_body_is("issues", &issue));
        assert!(!github_body_is("pull_request", &issue), "an issue resent as a pull request");
        assert!(!github_body_is("issue_comment", &issue), "a comment needs its comment");
        assert!(!github_body_is("star", &issue), "an event intake doesn't know");
        let pr = serde_json::json!({ "pull_request": null });
        assert!(!github_body_is("pull_request", &pr));
        // A sibling event's body, carrying more than the event claimed.
        let comment = serde_json::json!({ "issue": { "number": 1 }, "comment": { "id": 2 } });
        assert!(github_body_is("issue_comment", &comment) && !github_body_is("issues", &comment));
        let review = serde_json::json!({ "pull_request": { "number": 1 }, "review": { "state": "approved" } });
        assert!(github_body_is("pull_request_review", &review) && !github_body_is("pull_request", &review));
        let dispatch = serde_json::json!({ "ref": "refs/heads/main", "inputs": {} });
        assert!(!github_body_is("push", &dispatch), "a workflow_dispatch isn't a push");
        let create = serde_json::json!({ "ref": "main", "ref_type": "branch" });
        assert!(!github_body_is("push", &create), "nor a create");
        let push = serde_json::json!({ "ref": "refs/heads/main", "after": "abc", "commits": [], "pusher": { "name": "a" } });
        assert!(github_body_is("push", &push));
        // #714 fifth review: a review thread isn't a pull request, nor a deployment a run.
        let thread = serde_json::json!({ "pull_request": { "number": 1 }, "thread": { "comments": [] } });
        assert!(!github_body_is("pull_request", &thread) && !github_body_is("pull_request_review", &thread));
        let status = serde_json::json!({ "deployment_status": {}, "deployment": {}, "check_run": {}, "workflow_run": {} });
        assert!(!github_body_is("check_run", &status) && !github_body_is("workflow_run", &status));
        let deployment = serde_json::json!({ "deployment": {}, "workflow_run": {} });
        assert!(!github_body_is("workflow_run", &deployment));
        assert!(github_body_is("deployment", &deployment));
        assert!(!github_body_is("deployment", &status), "a deployment's status isn't a deployment");
        assert!(github_body_is("check_run", &serde_json::json!({ "check_run": { "deployment": {} } })), "a run's own deployment is fine");
    }

    /// The design's "CI failed on PR" case: a failed check suite on a PR's branch.
    #[test]
    fn a_github_check_suite_becomes_its_fields() {
        let body = serde_json::json!({
            "action": "completed",
            "check_suite": {
                "status": "completed", "conclusion": "failure", "head_branch": "fix/thing",
                "head_sha": "abc123", "url": "https://api.github.com/x",
                "app": { "name": "GitHub Actions" },
                "pull_requests": [{ "number": 42 }]
            },
            "repository": { "full_name": "acme/app" },
            "sender": { "login": "octo\u{202e}cat" }
        });
        let f = github_fields("check_suite", &body);
        assert_eq!(f["check"]["conclusion"], "failure");
        assert_eq!(f["check"]["name"], "GitHub Actions");
        assert_eq!(f["branch"], "fix/thing");
        assert_eq!(f["pr"]["number"], 42);
        assert_eq!(f["repo"], "acme/app");
        assert_eq!(f["sender"], "octo cat", "a bidi override is stripped");
        assert!(fields_within(&f));
        assert_eq!(github_repo(&body).as_deref(), Some("acme/app"));
        let pr = serde_json::json!({
            "action": "opened",
            "pull_request": { "number": 7, "title": "t", "html_url": "https://github.com/acme/app/pull/7", "draft": false,
                "user": { "login": "a" }, "head": { "ref": "feat" }, "base": { "ref": "main" },
                "labels": [{ "name": "bug" }, { "name": "c,i" }] },
            "repository": { "full_name": "acme/app" }
        });
        let f = github_fields("pull_request", &pr);
        assert_eq!((f["pr"]["number"].as_i64(), f["labels"].as_str(), f["base"].as_str()), (Some(7), Some("bug,c i"), Some("main")));
        let push = serde_json::json!({ "ref": "refs/heads/main", "after": "def", "repository": { "full_name": "acme/app" } });
        assert_eq!(github_fields("push", &push)["branch"], "main");
        // #714 review M5: one prefix only, and a tag isn't a branch.
        let tricky = serde_json::json!({ "ref": "refs/heads/refs/heads/main", "repository": { "full_name": "acme/app" } });
        assert_eq!(github_fields("push", &tricky)["branch"], "refs/heads/main");
        let tag = serde_json::json!({ "ref": "refs/tags/v1", "repository": { "full_name": "acme/app" } });
        assert!(github_fields("push", &tag).get("branch").is_none());
        // A fork's PR from its own `main`: branch main, but a fork.
        let fork = serde_json::json!({
            "action": "opened",
            "pull_request": { "number": 8, "head": { "ref": "main", "repo": { "full_name": "evil/app" } }, "base": { "ref": "main" } },
            "repository": { "full_name": "acme/app" }
        });
        let f = github_fields("pull_request", &fork);
        assert_eq!((f["branch"].as_str(), f["head_repo"].as_str(), f["fork"].as_bool()), (Some("main"), Some("evil/app"), Some(true)));
        assert_eq!(github_fields("pull_request", &pr)["fork"], true, "a pull request with no head repository (a deleted fork): a fork");
        let own = serde_json::json!({ "pull_request": { "number": 9, "head": { "ref": "x", "repo": { "full_name": "acme/app" } } }, "repository": { "full_name": "acme/app" } });
        assert_eq!(github_fields("pull_request", &own)["fork"], false);
        // #714 review M6: many long labels still fit what a node may send.
        let many = serde_json::json!({
            "issue": { "number": 1, "labels": (0..20).map(|i| serde_json::json!({ "name": format!("{i:02}-{}", "l".repeat(60)) })).collect::<Vec<_>>() },
            "repository": { "full_name": "acme/app" }
        });
        let f = github_fields("issues", &many);
        assert!(fields_within(&f), "{}", f["labels"]);
        assert!(f["labels"].as_str().unwrap().split(',').all(|l| l.len() == 63), "whole labels only");
    }
}
