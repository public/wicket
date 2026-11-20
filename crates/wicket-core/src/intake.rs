//! Webhook intake (#578 step 4; docs/explanation/trigger-intake.md): what `wicket node intake`
//! checks of a delivery and what it keeps of one. Everything here reads attacker-written bytes: a
//! verified signature says the sender had the secret, not that the content is safe. So a delivery
//! becomes a small, capped set of fields, stripped of control characters, and nothing else of the
//! body goes further than its sha256.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The largest body intake reads (bytes): past it, the delivery is refused unread.
pub const MAX_BODY: usize = 1 << 20;
/// A generic webhook's fields: at most this many top-level keys …
pub const MAX_GENERIC_FIELDS: usize = 32;
/// … each value at most this many bytes.
pub const MAX_GENERIC_VALUE: usize = 512;
/// A GitHub field's text: at most this many bytes.
pub const MAX_GITHUB_TEXT: usize = 256;
/// A GitHub delivery's labels: at most this many.
pub const MAX_LABELS: usize = 20;
/// The longest delivery id kept (a sender's header; longer is refused).
pub const MAX_DELIVERY: usize = 128;
/// GitHub's signature header (`sha256=<hex>` of the HMAC-SHA256 of the raw body), and the generic
/// webhook's (`sha256=<hex>` of the HMAC-SHA256 of [`generic_signed`]: the time, the delivery id
/// and the body).
pub const GITHUB_SIGNATURE: &str = "x-hub-signature-256";
pub const GENERIC_SIGNATURE: &str = "x-wicket-signature-256";
/// GitHub's event and delivery headers; the generic webhook's delivery header.
pub const GITHUB_EVENT: &str = "x-github-event";
pub const GITHUB_DELIVERY: &str = "x-github-delivery";
pub const GENERIC_DELIVERY: &str = "x-wicket-delivery";

/// One trigger a node's intake serves, as the control host sends it (protocol 20's `IntakeSync`).
/// The secret is held in memory only, on the node and in `wicket node intake`.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntakeTrigger {
    pub trigger: String,
    /// `webhook` or `github`.
    pub kind: String,
    pub token_sha256: String,
    /// The verify secret's value (HMAC key).
    pub secret: String,
    /// GitHub's: the repository (`owner/name`) and the events listened to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<String>,
    /// Served here, but its secret couldn't be read this time: its deliveries are answered 503
    /// (try later), not 404, and nothing counts as a failure (#714 review F5).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unavailable: bool,
}

impl std::fmt::Debug for IntakeTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntakeTrigger")
            .field("trigger", &self.trigger)
            .field("kind", &self.kind)
            .field("repo", &self.repo)
            .field("events", &self.events)
            .finish_non_exhaustive()
    }
}

/// A verified delivery, as intake keeps it and the node hands it to the control host.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct IntakeEvent {
    /// The node's spool id (what the control host acks).
    pub id: String,
    pub trigger: String,
    /// GitHub's event name (`check_suite`), or `webhook`.
    pub kind: String,
    pub delivery: String,
    /// When intake verified it (Unix s).
    pub received_at: i64,
    pub fields: Value,
    pub raw_sha256: String,
    pub bytes: u64,
}

/// What a node's intake refused since the last sync, counted: deliveries that never became events.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IntakeRefused {
    /// An unknown trigger, or a token that doesn't match.
    pub token: u64,
    pub signature: u64,
    pub rate: u64,
    /// Too large, malformed, or the spool full.
    pub other: u64,
}

impl IntakeRefused {
    pub fn total(&self) -> u64 {
        self.token + self.signature + self.rate + self.other
    }
}

/// HMAC-SHA256 (RFC 2104) of `msg` under `key`.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let pad = |x: u8| k.iter().map(|b| b ^ x).collect::<Vec<u8>>();
    let inner = Sha256::new().chain_update(pad(0x36)).chain_update(msg).finalize();
    Sha256::new().chain_update(pad(0x5c)).chain_update(inner).finalize().into()
}

/// Whether two byte strings are equal, in time that depends only on their lengths.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether `header` (`sha256=<hex>`, as GitHub sends it) is the HMAC-SHA256 of `body` under
/// `secret`. Anything else (no prefix, bad hex, another length) is not.
pub fn signature_ok(secret: &[u8], body: &[u8], header: Option<&str>) -> bool {
    if secret.len() < MIN_SECRET {
        return false;
    }
    let Some(h) = header.and_then(|h| h.trim().strip_prefix("sha256=")) else { return false };
    let Ok(sig) = hex::decode(h.trim()) else { return false };
    same(&sig, &hmac_sha256(secret, body))
}

/// The shortest verify secret (bytes) intake uses: an empty or short key would let anyone forge a
/// signature (#714 review E).
pub const MIN_SECRET: usize = 16;

/// Whether `secret` is long enough to verify with.
pub fn secret_ok(secret: &str) -> bool {
    secret.len() >= MIN_SECRET
}

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
        _ => return None,
    })
}

/// Whether `body` is a payload of GitHub `event`: it has that event's own object (and, for a
/// review or a comment, theirs too).
pub fn github_body_is(event: &str, body: &Value) -> bool {
    let Some(p) = github_event_object(event) else { return false };
    let extra = match event {
        "pull_request_review" => body.pointer("/review").is_some(),
        "pull_request_review_comment" | "issue_comment" => body.pointer("/comment").is_some(),
        _ => true,
    };
    body.pointer(p).is_some_and(|v| !v.is_null()) && extra
}

/// The generic webhook's timestamp header (Unix seconds), signed with the body.
pub const GENERIC_TIMESTAMP: &str = "x-wicket-timestamp";
/// How far a generic delivery's timestamp may be from intake's clock (s), either way.
pub const GENERIC_WINDOW_SECS: i64 = 300;

/// What a generic webhook's sender signs: `v1:<timestamp>:<length of the delivery id>:<delivery
/// id>:` then the raw body (the id empty, length 0, if it sends none). The timestamp and the id are
/// under the MAC, so a captured delivery can't be sent again later, or under another id; the id's
/// length is too, so a capture can't be split differently between id and body (#714 review F1).
pub fn generic_signed(timestamp: i64, delivery: &str, body: &[u8]) -> Vec<u8> {
    let mut m = format!("v1:{timestamp}:{}:{delivery}:", delivery.len()).into_bytes();
    m.extend_from_slice(body);
    m
}

/// The `X-Wicket-Signature-256` a sender sends (`sha256=<hex>`).
pub fn generic_signature(secret: &[u8], timestamp: i64, delivery: &str, body: &[u8]) -> String {
    format!("sha256={}", hex::encode(hmac_sha256(secret, &generic_signed(timestamp, delivery, body))))
}

/// Why a generic delivery's signature doesn't pass, if it doesn't: its timestamp missing, malformed
/// or outside [`GENERIC_WINDOW_SECS`] of `now`, or its MAC over [`generic_signed`] wrong.
pub fn generic_check(
    secret: &[u8],
    timestamp: Option<&str>,
    delivery: Option<&str>,
    body: &[u8],
    signature: Option<&str>,
    now: i64,
) -> Result<(), &'static str> {
    let ts = timestamp.and_then(|t| t.trim().parse::<i64>().ok()).ok_or("no timestamp")?;
    if (now - ts).abs() > GENERIC_WINDOW_SECS {
        return Err("timestamp outside the window");
    }
    let signed = generic_signed(ts, delivery.map(str::trim).unwrap_or(""), body);
    if signature_ok(secret, &signed, signature) {
        Ok(())
    } else {
        Err("bad signature")
    }
}

/// The sha256 (hex) of a trigger URL's token: what the ledger and intake keep of it.
pub fn token_sha256(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// A new trigger URL token: 32 random bytes, URL-safe base64 without padding (43 characters).
pub fn new_token() -> Result<String, String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| format!("random: {e}"))?;
    Ok(base64url(&b))
}

fn base64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = c.iter().enumerate().fold(0u32, |n, (i, x)| n | (u32::from(*x) << (16 - 8 * i)));
        for i in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// Whether `s` is a token's shape (what `new_token` makes): checked before hashing, so a path
/// can't make intake hash a megabyte.
pub fn token_shape(s: &str) -> bool {
    s.len() == 43 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A delivery id as kept: the sender's (`X-GitHub-Delivery`, `X-Wicket-Delivery`) if it is
/// printable ASCII of at most [`MAX_DELIVERY`] bytes, else the body's sha256 (so a resent body is
/// the same delivery). None if the sender's id is there but malformed.
pub fn delivery_id(header: Option<&str>, body: &[u8]) -> Option<String> {
    match header.map(str::trim) {
        None | Some("") => Some(format!("sha256:{}", hex::encode(Sha256::digest(body)))),
        Some(h) if h.len() <= MAX_DELIVERY && h.bytes().all(|b| b.is_ascii_graphic()) => Some(h.to_string()),
        Some(_) => None,
    }
}

/// Text from a delivery as kept: control characters stripped, cut at `max` bytes (on a char
/// boundary).
pub fn keep_text(s: &str, max: usize) -> String {
    let mut v = crate::text::strip(s);
    if v.len() > max {
        let mut cut = max;
        while !v.is_char_boundary(cut) {
            cut -= 1;
        }
        v.truncate(cut);
    }
    v
}

fn generic_key(k: &str) -> bool {
    !k.is_empty() && k.len() <= 64 && k.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.'))
}

/// A generic webhook's fields: the top-level scalars of a JSON object body (strings, numbers,
/// bools), at most [`MAX_GENERIC_FIELDS`], keys `[a-z0-9_.-]` of at most 64 bytes, strings cut at
/// [`MAX_GENERIC_VALUE`], the first by key order kept. Anything else in the body (nested values,
/// other keys) is dropped. A body that isn't a JSON object gives no fields.
pub fn generic_fields(body: &[u8]) -> Value {
    let mut out = Map::new();
    let Ok(Value::Object(m)) = serde_json::from_slice::<Value>(body) else { return Value::Object(out) };
    // In key order, whatever order the body had (and whether serde_json keeps it): which keys
    // are kept under the cap doesn't depend on how the sender ordered them.
    let mut entries: Vec<(String, Value)> = m.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in entries {
        if out.len() >= MAX_GENERIC_FIELDS {
            break;
        }
        // A dotted key would read as a nested field to a filter or a template: kept only plain.
        if !generic_key(&k) || k.contains('.') {
            continue;
        }
        let v = match v {
            Value::String(s) => Value::String(keep_text(&s, MAX_GENERIC_VALUE)),
            Value::Number(n) => Value::Number(n),
            Value::Bool(b) => Value::Bool(b),
            _ => continue,
        };
        out.insert(k, v);
    }
    Value::Object(out)
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

/// The sha256 (hex) of a delivery's raw body: all of the body that is kept.
pub fn body_sha256(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// Whether a field set is within what intake makes (a check the control host applies again to what
/// a node sends: a node is trusted only as far as its own triggers).
pub fn fields_within(fields: &Value) -> bool {
    fn walk(v: &Value, depth: usize, count: &mut usize) -> bool {
        *count += 1;
        if *count > 4 * MAX_GENERIC_FIELDS || depth > 3 {
            return false;
        }
        match v {
            Value::Object(m) => m.iter().all(|(k, v)| generic_key(k) && walk(v, depth + 1, count)),
            Value::String(s) => s.len() <= MAX_GENERIC_VALUE && !s.chars().any(crate::text::is_unsafe),
            Value::Number(_) | Value::Bool(_) => true,
            _ => false,
        }
    }
    let mut count = 0;
    fields.is_object() && walk(fields, 0, &mut count)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef-key";
    const OTHER: &[u8] = b"0123456789abcdef-other";

    /// RFC 4231's test cases 1, 2 and 6 (a key longer than a block), and GitHub's documented example.
    #[test]
    fn hmac_sha256_is_rfc_4231s() {
        let h = |k: &[u8], m: &[u8]| hex::encode(hmac_sha256(k, m));
        assert_eq!(h(&[0x0b; 20], b"Hi There"), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(h(b"Jefe", b"what do ya want for nothing?"), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(
            h(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First"),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        // docs.github.com, "Validating webhook deliveries".
        assert!(signature_ok(
            b"It's a Secret to Everybody",
            b"Hello, World!",
            Some("sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17")
        ));
    }

    #[test]
    fn only_the_right_signature_passes() {
        let sig = format!("sha256={}", hex::encode(hmac_sha256(KEY, b"body")));
        assert!(signature_ok(KEY, b"body", Some(&sig)));
        assert!(!signature_ok(KEY, b"body ", Some(&sig)), "another body");
        assert!(!signature_ok(OTHER, b"body", Some(&sig)), "another key");
        assert!(!signature_ok(KEY, b"body", Some(&sig[7..])), "no prefix");
        assert!(!signature_ok(KEY, b"body", Some("sha256=zz")), "not hex");
        assert!(!signature_ok(KEY, b"body", Some(&sig[..sig.len() - 2])), "short");
        assert!(!signature_ok(KEY, b"body", None));
        assert!(same(b"abc", b"abc") && !same(b"abc", b"abd") && !same(b"abc", b"ab"));
    }

    /// #714 review H2: a generic delivery's timestamp and id are under its MAC, so it can't be sent
    /// again later or under another id, and only within the window.
    #[test]
    fn a_generic_signature_binds_its_time_and_id() {
        let sig = generic_signature(KEY, 1000, "d-1", b"{}");
        let ok = |ts: &str, id: Option<&str>, body: &[u8], now: i64| generic_check(KEY, Some(ts), id, body, Some(&sig), now);
        assert_eq!(ok("1000", Some("d-1"), b"{}", 1000), Ok(()));
        assert_eq!(ok("1000", Some("d-1"), b"{}", 1299), Ok(()));
        assert_eq!(ok("1000", Some("d-1"), b"{}", 1301), Err("timestamp outside the window"), "too late");
        assert_eq!(ok("1000", Some("d-1"), b"{}", 699), Err("timestamp outside the window"), "too early");
        assert_eq!(ok("1000", Some("d-2"), b"{}", 1000), Err("bad signature"), "another id: a replay");
        assert_eq!(ok("1001", Some("d-1"), b"{}", 1000), Err("bad signature"), "another time");
        assert_eq!(ok("1000", None, b"{}", 1000), Err("bad signature"), "the id dropped");
        assert_eq!(generic_check(KEY, None, Some("d-1"), b"{}", Some(&sig), 1000), Err("no timestamp"));
        assert_eq!(generic_check(KEY, Some("x"), Some("d-1"), b"{}", Some(&sig), 1000), Err("no timestamp"));
    }

    /// #714 review F1: a capture can't be replayed by moving the boundary between its id and its
    /// body (an id with a `:` and the body's start).
    #[test]
    fn a_capture_cant_be_split_differently() {
        let sig = generic_signature(KEY, 1000, "d-1", br#"{"a":1}"#);
        let split = |id: &str, body: &[u8]| generic_check(KEY, Some("1000"), Some(id), body, Some(&sig), 1000);
        assert_eq!(split("d-1", br#"{"a":1}"#), Ok(()));
        assert_eq!(split(r#"d-1:{"a""#, b"1}"), Err("bad signature"));
        assert_eq!(split("d", br#"1:{"a":1}"#), Err("bad signature"));
    }

    /// #714 review E: an empty or short key verifies nothing.
    #[test]
    fn a_short_key_verifies_nothing() {
        let sig = format!("sha256={}", hex::encode(hmac_sha256(b"", b"body")));
        assert!(!signature_ok(b"", b"body", Some(&sig)));
        let short = generic_signature(b"k", 1, "", b"b");
        assert_eq!(generic_check(b"k", Some("1"), None, b"b", Some(&short), 1), Err("bad signature"));
        assert!(!secret_ok("short") && secret_ok(&"x".repeat(MIN_SECRET)));
    }

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
    }

    #[test]
    fn tokens_are_unguessable_and_shaped() {
        let (a, b) = (new_token().unwrap(), new_token().unwrap());
        assert_ne!(a, b);
        assert!(token_shape(&a) && token_shape(&b), "{a}");
        assert!(!token_shape("short") && !token_shape(&format!("{}!", &a[..42])));
        assert_eq!(token_sha256(&a).len(), 64);
        assert_eq!(base64url(b"\xfb\xff"), "-_8");
    }

    #[test]
    fn delivery_ids_are_the_senders_or_the_bodys() {
        assert_eq!(
            delivery_id(Some("72d3162e-cc78-11e3-81ab-4c9367dc0958"), b"x").as_deref(),
            Some("72d3162e-cc78-11e3-81ab-4c9367dc0958")
        );
        let a = delivery_id(None, b"x").unwrap();
        assert_eq!(a, delivery_id(Some(""), b"x").unwrap(), "a resent body is the same delivery");
        assert_ne!(a, delivery_id(None, b"y").unwrap());
        assert_eq!(delivery_id(Some("a b"), b"x"), None, "not printable as one word");
        assert_eq!(delivery_id(Some(&"a".repeat(129)), b"x"), None);
    }

    /// A generic body keeps only top-level scalars with plain keys, capped and stripped.
    #[test]
    fn a_generic_body_keeps_little() {
        let mut m = serde_json::Map::new();
        for i in 0..40 {
            m.insert(format!("k{i:02}"), Value::from(i));
        }
        m.insert("Bad Key".into(), "x".into());
        m.insert("a.b".into(), "nested-looking".into());
        m.insert("nested".into(), serde_json::json!({ "x": 1 }));
        m.insert("aa_text".into(), Value::String(format!("\u{1b}[31m{}", "y".repeat(600))));
        let f = generic_fields(&serde_json::to_vec(&Value::Object(m)).unwrap());
        let o = f.as_object().unwrap();
        assert_eq!(o.len(), MAX_GENERIC_FIELDS);
        assert!(!o.contains_key("Bad Key") && !o.contains_key("a.b") && !o.contains_key("nested"));
        let t = o["aa_text"].as_str().unwrap();
        assert!(t.len() <= MAX_GENERIC_VALUE && !t.contains('\u{1b}'), "{t}");
        assert!(fields_within(&f));
        assert_eq!(generic_fields(b"[1,2]"), serde_json::json!({}));
        assert_eq!(generic_fields(b"not json"), serde_json::json!({}));
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

    /// What a node sends is checked again: no deep nesting, no long or unsafe text, no odd keys.
    #[test]
    fn fields_from_a_node_are_held_to_intakes_shape() {
        assert!(fields_within(&serde_json::json!({ "a": 1, "b": { "c": "x" } })));
        assert!(!fields_within(&serde_json::json!({ "a": "x".repeat(600) })));
        assert!(!fields_within(&serde_json::json!({ "a": "\u{1b}" })));
        assert!(!fields_within(&serde_json::json!({ "A": 1 })));
        assert!(!fields_within(&serde_json::json!({ "a": [1] })));
        assert!(!fields_within(&serde_json::json!({ "a": { "b": { "c": { "d": 1 } } } })));
        assert!(!fields_within(&serde_json::json!("x")));
    }
}
