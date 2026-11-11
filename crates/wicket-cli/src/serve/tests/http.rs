//! The console as a client on the network sees it: the pre-auth surface, headers, sign-in limits,
//! sessions, HTTP bounds, TLS, and a fuzz test over request routing.

use super::*;
use crate::serve::web::{ASSETS, CSP, HSTS};
use http_body_util::BodyExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PEER: &str = "127.0.0.1:50000";

async fn call_from(
    state: &State,
    peer: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (StatusCode, HeaderMap, String) {
    let mut b = Request::builder().method(method).uri(path);
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        b = b.header("host", "localhost:8787");
    }
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    let req = b.body(Full::new(Bytes::copy_from_slice(body))).unwrap();
    let r = route(req, state, peer.parse().unwrap()).await;
    let (parts, body) = r.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    (parts.status, parts.headers, String::from_utf8_lossy(&bytes).into_owned())
}

async fn call(state: &State, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> (StatusCode, HeaderMap, String) {
    call_from(state, PEER, method, path, headers, body).await
}

/// A browser's POST: the CSRF header, our origin, JSON.
async fn post_json(state: &State, path: &str, cookie: Option<&str>, body: &Value) -> (StatusCode, HeaderMap, String) {
    post_json_from(state, PEER, path, cookie, body).await
}

async fn post_json_from(state: &State, peer: &str, path: &str, cookie: Option<&str>, body: &Value) -> (StatusCode, HeaderMap, String) {
    let c = cookie.map(|c| format!("__Host-wicket_sid={c}"));
    let mut h = vec![("x-wicket-csrf", "1"), ("origin", ORIGIN), ("content-type", "application/json")];
    if let Some(c) = &c {
        h.push(("cookie", c.as_str()));
    }
    call_from(state, peer, "POST", path, &h, body.to_string().as_bytes()).await
}

fn json_of(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or(Value::Null)
}

/// Every path the console has ever answered, and some it never did.
const ROUTES: &[&str] = &[
    "/api/me",
    "/api/state",
    "/api/register/begin",
    "/api/register/finish",
    "/api/action/begin",
    "/api/action/finish",
    "/api/decide/begin",
    "/api/decide/finish",
    "/api/logout",
    "/api/runs",
    "/api",
    "/admin",
    "/.env",
    "/favicon.ico",
    "/static/",
    "/static/console.js",
    "/../../etc/passwd",
    "/%2e%2e/ledger.db",
];
const METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"];

#[tokio::test]
async fn unauthenticated_requests_reach_only_the_sign_in_surface() {
    let t = setup("preauth");
    t.running("run_secret", "lead");
    let op = wicket_core::Op::egress(&TenantId::single(), &RunId("run_secret".into()), "z", "GET", "a.example", "/x");
    let (rid, _) = t.ledger().ask(&op, "x", false, None).unwrap();
    // Sessions that don't count: none, garbage, a revoked one, an idle one, an expired one.
    let l = t.ledger();
    let mk = |last_seen: i64, expires: i64| {
        let token = random_hex(32);
        l.add_console_session(
            &TenantId::single(),
            &ConsoleSession {
                id: session_id(&token),
                kind: "operator".into(),
                credential: Some(t.cred.clone()),
                client: "192.0.2.1".into(),
                created_at: last_seen,
                last_seen_at: last_seen,
                expires_at: expires,
            },
        )
        .unwrap();
        token
    };
    let now = wicket_store::now();
    let idle = mk(now - SESSION_IDLE - 1, now + 3600);
    let expired = mk(now - 10, now - 1);
    let revoked = mk(now, now + 3600);
    l.revoke_console_sessions(&TenantId::single(), Some(&session_id(&revoked)), "host").unwrap();
    let cookies: Vec<Option<String>> = vec![None, Some("nonsense".into()), Some("ab".repeat(32)), Some(idle), Some(expired), Some(revoked)];
    let secrets = ["run_secret", &t.cred, "laptop", "spiffe", env!("CARGO_PKG_VERSION"), "a.example", &rid];
    for cookie in &cookies {
        let c = cookie.as_ref().map(|c| format!("__Host-wicket_sid={c}"));
        for path in ROUTES {
            for method in METHODS {
                let mut h = vec![("x-wicket-csrf", "1"), ("origin", ORIGIN)];
                if let Some(c) = &c {
                    h.push(("cookie", c.as_str()));
                }
                let (status, headers, body) = call(&t.state, method, path, &h, b"{}").await;
                assert_eq!((status, body.as_str()), (StatusCode::UNAUTHORIZED, DENIED), "{method} {path} with {cookie:?}");
                assert!(!headers.contains_key("set-cookie"));
            }
        }
        // The public surface answers, and says nothing about the installation.
        let mut h = vec![];
        if let Some(c) = &c {
            h.push(("cookie", c.as_str()));
        }
        for path in ["/", "/manifest.webmanifest", "/static/icon.svg", "/static/icon-192.png"] {
            let (status, _, body) = call(&t.state, "GET", path, &h, b"").await;
            assert_eq!(status, StatusCode::OK, "{path}");
            for s in secrets {
                assert!(!body.contains(s), "{path} mentions {s:?}");
            }
        }
        let (status, headers, body) = post_json(&t.state, "/api/login/begin", cookie.as_deref(), &json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!headers.contains_key("set-cookie"));
        let v = json_of(&body);
        assert_eq!(v["publicKey"]["allowCredentials"], json!([]), "no credential ids before sign-in");
        assert_eq!(v["publicKey"]["userVerification"], "required");
        for s in secrets {
            assert!(!body.contains(s), "login/begin mentions {s:?}");
        }
    }
    // Requests for another host get the same answer, even for the page (DNS rebinding).
    for host in ["evil.example", "127.0.0.1:8787", "localhost", "localhost:8788"] {
        let (status, _, body) = call(&t.state, "GET", "/", &[("host", host)], b"").await;
        assert_eq!((status, body.as_str()), (StatusCode::UNAUTHORIZED, DENIED), "{host}");
    }
    // An enrolment link when none is open: the same 401.
    let (status, _, body) = call(&t.state, "GET", "/enrol?t=00", &[], b"").await;
    assert_eq!((status, body.as_str()), (StatusCode::UNAUTHORIZED, DENIED));
    // Sign-in looks the same whether or not any passkey is enrolled.
    let empty = setup("preauth-empty");
    empty.ledger().reset_operator_credentials(&TenantId::single()).unwrap();
    let (s1, _, b1) = post_json(&empty.state, "/api/login/begin", None, &json!({})).await;
    let (s2, _, b2) = post_json(&t.state, "/api/login/begin", None, &json!({})).await;
    let shape = |b: &str| {
        let mut v = json_of(b);
        v["publicKey"]["challenge"] = Value::Null;
        v
    };
    assert_eq!((s1, shape(&b1)), (s2, shape(&b2)));
    assert_eq!(t.state.authed.load(Ordering::Relaxed), 0, "no request reached an authenticated handler");
}

#[tokio::test]
async fn every_response_carries_the_security_headers() {
    let mut t = setup("headers");
    let sid = t.sid.clone().unwrap();
    let cookie = format!("__Host-wicket_sid={sid}");
    let js = ASSETS.files.keys().find(|k| k.ends_with(".js")).unwrap().clone();
    for https in [false, true] {
        t.state.hsts = https;
        type Req<'a> = (&'a str, &'a str, Vec<(&'a str, &'a str)>);
        let requests: Vec<Req> = vec![
            ("GET", "/", vec![]),
            ("GET", &js, vec![]),
            ("GET", "/manifest.webmanifest", vec![]),
            ("GET", "/api/state", vec![]),
            ("GET", "/api/state", vec![("cookie", &cookie)]),
            ("GET", "/api/me", vec![("cookie", &cookie)]),
            ("GET", "/nope", vec![("cookie", &cookie)]),
            ("DELETE", "/api/state", vec![("cookie", &cookie)]),
            ("POST", "/api/logout", vec![("cookie", &cookie)]),
            ("GET", "/enrol?t=x", vec![]),
            ("OPTIONS", "/api/login/begin", vec![("origin", "https://evil.example"), ("access-control-request-method", "POST")]),
            ("GET", "/", vec![("host", "evil.example")]),
        ];
        for (method, path, h) in &requests {
            let (status, headers, _) = call(&t.state, method, path, h, b"").await;
            let get = |k: &str| headers.get(k).map(|v| v.to_str().unwrap().to_string());
            assert_eq!(get("content-security-policy").as_deref(), Some(CSP), "{method} {path} {status}");
            assert_eq!(get("x-content-type-options").as_deref(), Some("nosniff"));
            assert_eq!(get("referrer-policy").as_deref(), Some("no-referrer"));
            assert_eq!(get("cross-origin-opener-policy").as_deref(), Some("same-origin"));
            assert_eq!(get("x-frame-options").as_deref(), Some("DENY"));
            assert!(get("permissions-policy").is_some());
            assert!(get("cache-control").is_some());
            assert_eq!(get("strict-transport-security").as_deref(), https.then_some(HSTS), "{method} {path}");
            for k in headers.keys() {
                assert!(!k.as_str().starts_with("access-control-"), "{method} {path}: {k}");
                assert_ne!(k.as_str(), "server");
            }
        }
    }
    assert!(CSP.contains("default-src 'none'") && CSP.contains("script-src 'self';") && !CSP.contains("unsafe"));
    assert!(HSTS.contains("max-age=63072000") && HSTS.contains("includeSubDomains") && HSTS.contains("preload"));
    // Hashed assets are immutable; everything with data is no-store.
    let (_, h, _) = call(&t.state, "GET", &js, &[], b"").await;
    assert!(h["cache-control"].to_str().unwrap().contains("immutable"));
    let (_, h, _) = call(&t.state, "GET", "/api/state", &[("cookie", &cookie)], b"").await;
    assert_eq!(h["cache-control"], "no-store");
}

#[test]
fn the_page_has_no_inline_script_or_style_and_names_its_files_by_hash() {
    let page = std::str::from_utf8(&ASSETS.page).unwrap();
    assert!(!page.contains("<style") && !page.contains("style="), "inline style");
    assert!(!page.split_whitespace().any(|w| w.starts_with("on") && w.contains('=')), "inline event handlers");
    let scripts: Vec<&str> = page.match_indices("<script").map(|(i, _)| &page[i..]).collect();
    assert_eq!(scripts.len(), 1);
    assert!(scripts[0].starts_with("<script src=\"/static/console.") && scripts[0].contains("></script>"), "{}", scripts[0]);
    assert!(!page.contains("{{"), "every placeholder filled");
    for (path, a) in &ASSETS.files {
        if path.ends_with(".js") || path.ends_with(".css") {
            let digest = sha2::Sha256::digest(&a.body);
            assert!(path.contains(&hex::encode(digest)[..16]), "{path} is named by its hash");
            let sri = format!("sha256-{}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest));
            assert!(
                page.contains(&format!("href=\"{path}\" integrity=\"{sri}\""))
                    || page.contains(&format!("src=\"{path}\" integrity=\"{sri}\"")),
                "{path}"
            );
        }
    }
    let js = ASSETS.files.iter().find(|(k, _)| k.ends_with(".js")).map(|(_, a)| std::str::from_utf8(&a.body).unwrap()).unwrap();
    for bad in ["prompt(", "innerHTML", "eval(", "new Function", "document.write", "setAttribute(\"style\"", ".cssText"] {
        assert!(!js.contains(bad), "console.js uses {bad}");
    }
    // The manifest is valid, and every icon it names is served.
    let m: Value = serde_json::from_slice(&ASSETS.files["/manifest.webmanifest"].body).unwrap();
    assert_eq!((m["display"].as_str(), m["start_url"].as_str()), (Some("standalone"), Some("/")));
    for icon in m["icons"].as_array().unwrap() {
        let src = icon["src"].as_str().unwrap();
        let a = &ASSETS.files[src];
        assert_eq!(a.ctype, icon["type"].as_str().unwrap());
        if a.ctype == "image/png" {
            assert!(a.body.starts_with(b"\x89PNG\r\n\x1a\n"));
            let w = u32::from_be_bytes(a.body[16..20].try_into().unwrap());
            assert_eq!(icon["sizes"].as_str().unwrap(), format!("{w}x{w}"));
        }
    }
    assert!(page.contains("rel=\"manifest\" href=\"/manifest.webmanifest\"") && page.contains("apple-touch-icon"));
}

/// An assertion `t` signs for a login challenge, from a fresh /api/login/begin.
async fn login_assertion(t: &mut T, peer: &str) -> Value {
    let (_, _, b) = post_json_from(&t.state, peer, "/api/login/begin", None, &json!({})).await;
    let ch = json_of(&b)["publicKey"]["challenge"].as_str().unwrap().to_string();
    t.sign(&ch)
}

fn audits(t: &T, kind: &str) -> Vec<Value> {
    t.audit_kinds().into_iter().filter(|(k, _)| k == kind).map(|(_, b)| b).collect()
}

#[tokio::test]
async fn sign_in_sets_a_host_only_cookie_and_rotates_the_session() {
    let mut t = setup("signin");
    let old = t.sid.clone().unwrap();
    let a = login_assertion(&mut t, PEER).await;
    let (status, headers, body) = post_json(&t.state, "/api/login/finish", Some(&old), &a).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let cookie = headers["set-cookie"].to_str().unwrap().to_string();
    let parts: Vec<&str> = cookie.split("; ").collect();
    assert!(parts[0].starts_with("__Host-wicket_sid=") && parts[0].len() == "__Host-wicket_sid=".len() + 64, "{cookie}");
    for want in ["Path=/", "Secure", "HttpOnly", "SameSite=Strict", &format!("Max-Age={SESSION_ABSOLUTE}")] {
        assert!(parts.contains(&want), "{cookie} lacks {want}");
    }
    assert!(!cookie.to_ascii_lowercase().contains("domain="));
    let new = token_of(&cookie);
    assert_ne!(new, old);
    // The session the browser had before signing in is over; the new one works.
    assert_eq!(
        call(&t.state, "GET", "/api/state", &[("cookie", &format!("__Host-wicket_sid={old}"))], b"").await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, _, body) = call(&t.state, "GET", "/api/me", &[("cookie", &format!("__Host-wicket_sid={new}"))], b"").await;
    assert_eq!((status, json_of(&body)["who"]["state"].as_str()), (StatusCode::OK, Some("operator")));
    let signed_in = audits(&t, "operator.signed_in");
    assert_eq!((signed_in.len(), signed_in[0]["client"].as_str()), (1, Some("127.0.0.1")));
    // Sign-out ends it and clears the cookie.
    let (_, h, _) = post_json(&t.state, "/api/logout", Some(&new), &json!({})).await;
    assert!(h["set-cookie"].to_str().unwrap().contains("Max-Age=0"));
    assert_eq!(call(&t.state, "GET", "/api/me", &[("cookie", &format!("__Host-wicket_sid={new}"))], b"").await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sign_in_failures_are_uniform_limited_locked_out_and_audited() {
    let mut t = setup("lockout");
    // Failures of every kind get the same answer.
    let good = login_assertion(&mut t, PEER).await;
    let mut wrong_sig = good.clone();
    wrong_sig["signature"] = json!(b64u(b"not a signature"));
    let mut unknown_cred = login_assertion(&mut t, PEER).await;
    unknown_cred["id"] = json!(b64u(b"someone else"));
    let failures = [json!({}), json!({ "challenge": "nope" }), wrong_sig, unknown_cred, good.clone()];
    let mut bodies = std::collections::BTreeSet::new();
    for (i, f) in failures.iter().enumerate() {
        let (status, headers, body) = post_json(&t.state, "/api/login/finish", None, f).await;
        if i == 4 {
            // The good assertion's challenge was consumed by the forged attempt that used it.
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{i}: {body}");
        assert!(!headers.contains_key("set-cookie"));
        bodies.insert(body);
    }
    assert_eq!(bodies.into_iter().collect::<Vec<_>>(), vec![json!({ "error": SIGN_IN_FAILED }).to_string()]);
    // Five failures in a row from one address: locked out, audited, and even a good assertion is
    // then refused.
    let failed = audits(&t, "operator.login_failed");
    assert_eq!(failed.len(), 5);
    assert!(failed.iter().any(|f| f["reason"].as_str().unwrap().contains("signature")), "{failed:?}");
    assert!(failed.iter().all(|f| f["client"] == "127.0.0.1"));
    let lock = audits(&t, "operator.lockout");
    assert_eq!((lock.len(), lock[0]["scope"].as_str(), lock[0]["seconds"].as_u64()), (1, Some("client"), Some(limits::LOCKOUT.as_secs())));
    let (status, headers, _) = post_json(&t.state, "/api/login/begin", None, &json!({})).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(headers["retry-after"].to_str().unwrap().parse::<u64>().unwrap() > 0);
    // Another address is not locked out by this one.
    let other = "192.0.2.77:4000";
    let a = login_assertion(&mut t, other).await;
    assert_eq!(post_json_from(&t.state, other, "/api/login/finish", None, &a).await.0, StatusCode::OK);

    // Per passkey: failures naming it from many addresses lock it out everywhere.
    for i in 0..limits::FAILURES_TO_LOCK {
        let peer = format!("198.51.100.{i}:4000");
        let mut a = login_assertion(&mut t, &peer).await;
        a["signature"] = json!(b64u(b"forged"));
        post_json_from(&t.state, &peer, "/api/login/finish", None, &a).await;
    }
    assert!(audits(&t, "operator.lockout").iter().any(|l| l["scope"] == "credential" && l["key"] == t.cred.as_str()));
    let fresh = "203.0.113.200:4000";
    let a = login_assertion(&mut t, fresh).await;
    let (status, _, body) = post_json_from(&t.state, fresh, "/api/login/finish", None, &a).await;
    assert_eq!(
        (status, json_of(&body)["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some(SIGN_IN_FAILED)),
        "a locked passkey can't sign in"
    );
    assert!(audits(&t, "operator.login_failed").last().unwrap()["reason"].as_str().unwrap().contains("locked"));

    // Throttled: too many attempts a minute from one address, even all well-formed.
    let busy = "192.0.2.150:4000";
    let mut last = StatusCode::OK;
    for _ in 0..=limits::IP_ATTEMPTS {
        last = post_json_from(&t.state, busy, "/api/login/begin", None, &json!({})).await.0;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn sign_in_without_user_verification_is_refused_like_any_failure() {
    let mut t = setup("no-uv");
    let (_, _, b) = post_json(&t.state, "/api/login/begin", None, &json!({})).await;
    let begin = json_of(&b);
    assert_eq!(begin["publicKey"]["userVerification"], "required");
    let ch = begin["publicKey"]["challenge"].as_str().unwrap().to_string();
    // A real signature over authenticator data that says "present" but not "verified".
    let a = t.sign_flags(&ch, 0x01);
    let (status, headers, body) = post_json(&t.state, "/api/login/finish", None, &a).await;
    assert_eq!((status, body), (StatusCode::UNAUTHORIZED, json!({ "error": SIGN_IN_FAILED }).to_string()));
    assert!(!headers.contains_key("set-cookie"));
    assert_eq!(audits(&t, "operator.login_failed").len(), 1);
    assert!(audits(&t, "operator.signed_in").is_empty());
}

#[tokio::test]
async fn the_challenge_store_is_bounded() {
    let t = setup("challenges");
    // One client keeps at most a few sign-in challenges: new ones replace its oldest.
    let mut first = None;
    for i in 0..(MAX_CHALLENGES_PER_OWNER + 3) {
        let (_, _, b) = post_json_from(&t.state, "192.0.2.10:1", "/api/login/begin", None, &json!({})).await;
        if i == 0 {
            first = json_of(&b)["publicKey"]["challenge"].as_str().map(String::from);
        }
    }
    {
        let c = t.state.challenges.lock().unwrap();
        assert_eq!(c.values().filter(|p| p.owner == "192.0.2.10").count(), MAX_CHALLENGES_PER_OWNER);
        assert!(!c.contains_key(first.as_deref().unwrap()), "the oldest went");
    }
    // In all: when the store is full, sign-in is refused rather than growing it.
    for i in 0..MAX_CHALLENGES {
        let ip: IpAddr = std::net::Ipv4Addr::from(0x0a00_0000 + i as u32).into();
        new_challenge(&t.state, random_bytes(32), Purpose::Login, None, limits::ip_key(ip));
    }
    assert!(t.state.challenges.lock().unwrap().len() <= MAX_CHALLENGES);
    let (status, _, _) = post_json_from(&t.state, "192.0.2.99:1", "/api/login/begin", None, &json!({})).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn sessions_expire_and_are_revocable_from_the_host() {
    let t = setup("sessions");
    let sid = t.sid.clone().unwrap();
    let cookie = format!("__Host-wicket_sid={sid}");
    let state_ok = |c: &str| {
        let c = c.to_string();
        let st = &t.state;
        async move { call(st, "GET", "/api/state", &[("cookie", &c)], b"").await.0 }
    };
    assert_eq!(state_ok(&cookie).await, StatusCode::OK);
    // Listed on the host, with the client it signed in from; revoked there, it stops at once.
    let l = t.ledger();
    let live = l.console_sessions(&TenantId::single(), wicket_store::now()).unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(
        (live[0].id.as_str(), live[0].credential.as_deref(), live[0].client.as_str()),
        (session_id(&sid).as_str(), Some(t.cred.as_str()), "127.0.0.1")
    );
    assert_ne!(live[0].id, sid, "the ledger holds a hash, not the cookie");
    l.revoke_console_sessions(&TenantId::single(), Some(&live[0].id[..12]), "host").unwrap();
    assert_eq!(state_ok(&cookie).await, StatusCode::UNAUTHORIZED);
    // Idle and absolute expiry.
    let now = wicket_store::now();
    for (last_seen, expires, want) in [
        (now - SESSION_IDLE + 30, now + 60, StatusCode::OK),
        (now - SESSION_IDLE, now + 60, StatusCode::UNAUTHORIZED),
        (now, now, StatusCode::UNAUTHORIZED),
    ] {
        let token = random_hex(32);
        l.add_console_session(
            &TenantId::single(),
            &ConsoleSession {
                id: session_id(&token),
                kind: "operator".into(),
                credential: Some(t.cred.clone()),
                client: "127.0.0.1".into(),
                created_at: last_seen,
                last_seen_at: last_seen,
                expires_at: expires,
            },
        )
        .unwrap();
        assert_eq!(state_ok(&format!("__Host-wicket_sid={token}")).await, want, "{last_seen} {expires}");
    }
    // Requests keep a session alive (its last-seen time moves).
    let token = random_hex(32);
    let id = session_id(&token);
    let s = ConsoleSession {
        id: id.clone(),
        kind: "operator".into(),
        credential: Some(t.cred.clone()),
        client: "127.0.0.1".into(),
        created_at: now - 600,
        last_seen_at: now - 600,
        expires_at: now + 600,
    };
    l.add_console_session(&TenantId::single(), &s).unwrap();
    assert_eq!(state_ok(&format!("__Host-wicket_sid={token}")).await, StatusCode::OK);
    assert!(l.console_session(&TenantId::single(), &id, now).unwrap().unwrap().last_seen_at >= now);
    // A passkey revoked on the host (operator reset) ends its sessions too.
    l.reset_operator_credentials(&TenantId::single()).unwrap();
    assert_eq!(state_ok(&format!("__Host-wicket_sid={token}")).await, StatusCode::UNAUTHORIZED);
}

/// A fresh host-issued enrolment link (its path), as `wicket operator enrol-link` makes.
fn host_link(t: &T, ttl_secs: i64) -> String {
    format!("/enrol?t={}", issue_enrol_link(&t.ledger(), &TenantId::single(), ttl_secs, "test host").unwrap())
}

/// Opens an enrolment link; the bootstrap session's token if it worked.
async fn open_link(t: &T, peer: &str, link: &str) -> Option<String> {
    let (status, headers, body) = call_from(&t.state, peer, "GET", link, &[], b"").await;
    if status != StatusCode::SEE_OTHER {
        assert_eq!((status, body.as_str()), (StatusCode::UNAUTHORIZED, DENIED), "a failed link looks like any 401");
        assert!(!headers.contains_key("set-cookie"));
        return None;
    }
    let cookie = headers["set-cookie"].to_str().unwrap();
    assert!(cookie.contains("Secure; HttpOnly; SameSite=Strict") && cookie.contains(&format!("Max-Age={BOOTSTRAP_TTL}")));
    Some(token_of(cookie))
}

/// What a browser returns from navigator.credentials.create for `challenge`: a new P-256 passkey,
/// user present and verified, "none" attestation.
fn attestation(challenge: &str, key: &SigningKey, id: &[u8]) -> Value {
    let cdj = json!({ "type": "webauthn.create", "challenge": challenge, "origin": ORIGIN, "crossOrigin": false }).to_string().into_bytes();
    let mut ad = sha2::Sha256::digest(b"localhost").to_vec();
    ad.push(0x01 | 0x04 | 0x40); // user present, user verified, attested credential data
    ad.extend_from_slice(&0u32.to_be_bytes());
    ad.extend_from_slice(&[0u8; 16]);
    ad.extend_from_slice(&(id.len() as u16).to_be_bytes());
    ad.extend_from_slice(id);
    let p = key.verifying_key().to_encoded_point(false);
    let cose = ciborium::Value::Map(vec![
        (1.into(), 2.into()),
        (3.into(), (-7).into()),
        ((-1).into(), 1.into()),
        ((-2).into(), ciborium::Value::Bytes(p.x().unwrap().to_vec())),
        ((-3).into(), ciborium::Value::Bytes(p.y().unwrap().to_vec())),
    ]);
    ciborium::ser::into_writer(&cose, &mut ad).unwrap();
    let att = ciborium::Value::Map(vec![
        ("fmt".into(), "none".into()),
        ("attStmt".into(), ciborium::Value::Map(vec![])),
        ("authData".into(), ciborium::Value::Bytes(ad)),
    ]);
    let mut att_bytes = Vec::new();
    ciborium::ser::into_writer(&att, &mut att_bytes).unwrap();
    json!({ "challenge": challenge, "name": "second phone", "clientDataJSON": b64u(&cdj), "attestationObject": b64u(&att_bytes) })
}

/// Registration step 1 for a session: the status and the challenge, if one was given.
async fn register_begin_as(t: &T, sid: &str) -> (StatusCode, Option<String>) {
    let (status, _, body) = post_json(&t.state, "/api/register/begin", Some(sid), &json!({})).await;
    (status, json_of(&body)["publicKey"]["challenge"].as_str().map(String::from))
}

#[tokio::test]
async fn the_enrolment_link_is_single_use_and_its_failures_look_like_any_401() {
    let t = setup("enrol");
    assert!(open_link(&t, PEER, "/enrol?t=wrong").await.is_none());
    assert!(open_link(&t, PEER, "/enrol").await.is_none());
    assert_eq!(audits(&t, "operator.enrol_failed").len(), 2);
    // setup() already has a passkey: a host link works anyway (another device).
    let link = host_link(&t, 600);
    assert_eq!(audits(&t, "operator.enrol_link_issued").len(), 1);
    let boot = open_link(&t, PEER, &link).await.expect("a fresh link works");
    let used = audits(&t, "operator.enrol_link_used");
    assert_eq!((used.len(), used[0]["client"].as_str()), (1, Some("127.0.0.1")));
    // It can enrol, and can't see anything.
    let c = format!("__Host-wicket_sid={boot}");
    let (status, _, body) = call(&t.state, "GET", "/api/me", &[("cookie", &c)], b"").await;
    assert_eq!((status, json_of(&body)["who"]["state"].as_str()), (StatusCode::OK, Some("bootstrap")));
    assert_eq!(call(&t.state, "GET", "/api/state", &[("cookie", &c)], b"").await.0, StatusCode::UNAUTHORIZED);
    let say = json!({ "action": "say", "run": "r", "text": "hi" });
    assert_eq!(post_json(&t.state, "/api/action/begin", Some(&boot), &say).await.0, StatusCode::UNAUTHORIZED);
    // Used: the same link is now just another 401, from anywhere.
    assert!(open_link(&t, PEER, &link).await.is_none());
    assert!(open_link(&t, "192.0.2.5:1", &link).await.is_none());
    // Expired: also just a 401.
    let old = host_link(&t, 0);
    assert!(open_link(&t, PEER, &old).await.is_none());
    assert_eq!(audits(&t, "operator.enrol_failed").len(), 5);
}

#[tokio::test]
async fn a_host_link_enrols_one_passkey_audited_with_the_link_and_client() {
    let t = setup("enrol-ok");
    let link = host_link(&t, 600);
    let boot = open_link(&t, "192.0.2.44:1", &link).await.unwrap();
    let (status, ch) = register_begin_as(&t, &boot).await;
    assert_eq!(status, StatusCode::OK);
    let key = SigningKey::random(&mut rand_core::OsRng);
    let (status, _, body) = post_json(&t.state, "/api/register/finish", Some(&boot), &attestation(&ch.unwrap(), &key, b"cred-2")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let creds = t.ledger().operator_credentials(&TenantId::single()).unwrap();
    assert_eq!(creds.len(), 2);
    assert!(creds.iter().any(|c| c.id == b64u(b"cred-2") && c.name == "second phone"));
    let added = audits(&t, "operator.passkey_added");
    assert_eq!(added.len(), 1);
    assert_eq!(added[0]["via"], "enrolment link");
    assert_eq!(added[0]["client"], "192.0.2.44");
    assert_eq!(added[0]["link"], audits(&t, "operator.enrol_link_used")[0]["link"]);
    assert_eq!(added[0]["link"].as_str().unwrap().len(), 16);
    // The enrolment session ended with its one job: no second passkey from the same link.
    let (status, ch) = register_begin_as(&t, &boot).await;
    assert_eq!((status, ch), (StatusCode::UNAUTHORIZED, None));
    assert!(open_link(&t, PEER, &link).await.is_none());
}

#[tokio::test]
async fn a_signed_in_operator_session_cannot_enrol_a_passkey() {
    let t = setup("enrol-op");
    let op = t.sid.clone().unwrap();
    // Begin: refused, no challenge.
    let (status, ch) = register_begin_as(&t, &op).await;
    assert_eq!((status, ch), (StatusCode::FORBIDDEN, None));
    // Finish: refused, even with a valid registration challenge (issued to an enrolment session).
    let boot = open_link(&t, PEER, &host_link(&t, 600)).await.unwrap();
    let ch = register_begin_as(&t, &boot).await.1.unwrap();
    let key = SigningKey::random(&mut rand_core::OsRng);
    let (status, _, _) = post_json(&t.state, "/api/register/finish", Some(&op), &attestation(&ch, &key, b"stolen")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // And without any session: the uniform 401.
    let (status, _, body) = post_json(&t.state, "/api/register/finish", None, &attestation(&ch, &key, b"anon")).await;
    assert_eq!((status, body.as_str()), (StatusCode::UNAUTHORIZED, DENIED));
    assert_eq!(t.ledger().operator_credentials(&TenantId::single()).unwrap().len(), 1, "nothing was added");
    assert!(audits(&t, "operator.passkey_added").is_empty());
}

#[tokio::test]
async fn posts_need_the_csrf_header_and_the_consoles_origin() {
    let t = setup("origin");
    let cookie = format!("__Host-wicket_sid={}", t.sid.clone().unwrap());
    let body = br#"{"action":"say","run":"run_x","text":"hi"}"#;
    let base = [("cookie", cookie.as_str()), ("content-type", "application/json")];
    let cases: Vec<(Vec<(&str, &str)>, StatusCode)> = vec![
        (vec![("origin", ORIGIN)], StatusCode::FORBIDDEN),
        (vec![("x-wicket-csrf", "1")], StatusCode::FORBIDDEN),
        (vec![("x-wicket-csrf", "1"), ("origin", "https://evil.example")], StatusCode::FORBIDDEN),
        (vec![("x-wicket-csrf", "1"), ("origin", "null")], StatusCode::FORBIDDEN),
        (vec![("x-wicket-csrf", "1"), ("origin", ORIGIN), ("sec-fetch-site", "cross-site")], StatusCode::FORBIDDEN),
        (vec![("x-wicket-csrf", "1"), ("origin", ORIGIN), ("sec-fetch-site", "same-origin")], StatusCode::NOT_FOUND),
    ];
    for (extra, want) in cases {
        let h: Vec<(&str, &str)> = base.iter().copied().chain(extra.iter().copied()).collect();
        let (status, _, b) = call(&t.state, "POST", "/api/action/begin", &h, body).await;
        assert_eq!(status, want, "{extra:?}: {b}");
    }
    // Sign-in too.
    let (status, _, _) =
        call(&t.state, "POST", "/api/login/begin", &[("origin", "https://evil.example"), ("x-wicket-csrf", "1")], b"{}").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// A small deterministic generator (xorshift64*), so a failure names a seed that reproduces it.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn pick<'a>(&mut self, xs: &[&'a str]) -> &'a str {
        xs[self.below(xs.len())]
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

#[tokio::test]
async fn fuzzed_requests_never_panic_or_reach_an_authenticated_handler() {
    let t = setup("fuzz");
    // The real session token is never used: the fuzzer has only what an outsider could have.
    let seed = std::env::var("WICKET_FUZZ_SEED").ok().and_then(|s| s.parse().ok()).unwrap_or(0x5eed_1234_abcd_0001u64);
    let mut rng = Rng(seed);
    let paths = [
        "/",
        "/enrol",
        "/api/me",
        "/api/state",
        "/api/login/begin",
        "/api/login/finish",
        "/api/register/begin",
        "/api/register/finish",
        "/api/action/begin",
        "/api/action/finish",
        "/api/decide/begin",
        "/api/logout",
        "/manifest.webmanifest",
        "/static/icon.svg",
        "//api/state",
        "/api/state/",
        "/API/STATE",
        "/api/state?x=1",
        "/api/%73tate",
        "/api/./state",
        "/api/../api/state",
        "*",
    ];
    let methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "PROPFIND", "get", "X"];
    let header_names = [
        "cookie",
        "x-wicket-csrf",
        "origin",
        "content-type",
        "x-forwarded-for",
        "host",
        "sec-fetch-site",
        "content-length",
        "transfer-encoding",
        "authorization",
    ];
    let values = [
        "1",
        "0",
        ORIGIN,
        "https://evil.example",
        "application/json",
        "text/plain",
        "localhost:8787",
        "evil.example",
        "same-origin",
        "__Host-wicket_sid=",
        "wicket_sid=",
        "chunked",
        "-1",
        "99999999999999999999",
        "",
        "Bearer x",
    ];
    let bodies: [&[u8]; 8] = [
        b"",
        b"{}",
        b"[]",
        b"null",
        br#"{"challenge":"AAAA","id":"AAAA","clientDataJSON":"e30","authenticatorData":"AAAA","signature":"AAAA"}"#,
        br#"{"action":"start_run","root":"manifests","manifest":"../../x.yaml"}"#,
        br#"{"action":"decide","id":"r-1","decision":"approve"}"#,
        b"\xff\xfe{",
    ];
    let mut statuses = std::collections::BTreeMap::new();
    for i in 0..4000 {
        let mut path = rng.pick(&paths).to_string();
        if rng.below(4) == 0 {
            let n = rng.below(8);
            path.push_str(&format!("/{}", hex::encode(rng.bytes(n))));
        }
        if rng.below(6) == 0 {
            path.push_str(&format!("?t={}", hex::encode(rng.bytes(24))));
        }
        let method = rng.pick(&methods);
        let mut b = Request::builder().method(method).uri(path.as_str());
        if rng.below(10) != 0 {
            b = b.header("host", "localhost:8787");
        }
        if rng.below(3) == 0 {
            b = b.header("x-wicket-csrf", "1").header("origin", ORIGIN);
        }
        for _ in 0..rng.below(6) {
            let name = rng.pick(&header_names);
            let mut v = rng.pick(&values).to_string();
            if v.ends_with('=') {
                let n = if rng.below(2) == 0 { 32 } else { rng.below(40) };
                v.push_str(&hex::encode(rng.bytes(n)));
            }
            b = b.header(name, v);
        }
        let n = rng.below(300);
        let body = if rng.below(5) == 0 { rng.bytes(n) } else { bodies[rng.below(bodies.len())].to_vec() };
        let Ok(req) = b.body(Full::new(Bytes::from(body))) else { continue };
        let peer = format!("192.0.2.{}:{}", rng.below(250), 1000 + rng.below(60000));
        let r = route(req, &t.state, peer.parse().unwrap()).await;
        let status = r.status();
        *statuses.entry(status.as_u16()).or_insert(0) += 1;
        assert!(!r.headers().contains_key("set-cookie"), "seed {seed:#x}, request {i}: {method} {path} got a cookie");
        assert!(r.headers().contains_key("content-security-policy"));
        assert!([200, 401, 403, 400, 413, 429, 503].contains(&status.as_u16()), "seed {seed:#x}, request {i}: {method} {path} -> {status}");
        if status == StatusCode::OK {
            let p = path.split('?').next().unwrap();
            assert!(p == "/" || ASSETS.files.contains_key(p) || p == "/api/login/begin", "seed {seed:#x}: {method} {path} answered 200");
        }
    }
    assert_eq!(t.state.authed.load(Ordering::Relaxed), 0, "seed {seed:#x}: a fuzzed request reached an authenticated handler");
    assert!(statuses.len() >= 4, "the fuzzer exercised several outcomes: {statuses:?}");
    assert!(t.ledger().take_operator_messages("run_x").unwrap().is_empty());
}

// ---- over the network ----

async fn start(mut state: State, tweak: impl FnOnce(&mut State)) -> SocketAddr {
    tweak(&mut state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(net::run(listener, None, Arc::new(state)));
    addr
}

/// Writes `req` and reads until the server closes (or `wait` passes). Returns what came back.
async fn exchange(addr: SocketAddr, req: &[u8], wait: Duration) -> String {
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _ = s.write_all(req).await;
    let mut out = Vec::new();
    let _ = tokio::time::timeout(wait, s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

#[tokio::test]
async fn oversized_and_slow_requests_are_cut_off() {
    let t = setup("limits");
    let addr = start(t.state, |s| {
        s.limits.header_timeout = Duration::from_millis(300);
        s.limits.body_timeout = Duration::from_millis(300);
        s.limits.conn_lifetime = Duration::from_secs(1);
    })
    .await;
    let w = Duration::from_secs(5);
    // Headers too large, or too many.
    let big = format!("GET / HTTP/1.1\r\nhost: localhost:8787\r\nx-big: {}\r\n\r\n", "a".repeat(20_000));
    assert!(exchange(addr, big.as_bytes(), w).await.starts_with("HTTP/1.1 431"));
    let many: String = (0..100).map(|i| format!("x-h{i}: 1\r\n")).collect();
    let out = exchange(addr, format!("GET / HTTP/1.1\r\nhost: localhost:8787\r\n{many}\r\n").as_bytes(), w).await;
    assert!(out.starts_with("HTTP/1.1 431"), "{out}");
    // A declared body over the limit is refused without reading it.
    let req = format!(
        "POST /api/login/begin HTTP/1.1\r\nhost: localhost:8787\r\norigin: {ORIGIN}\r\nx-wicket-csrf: 1\r\ncontent-length: 10000000\r\nconnection: close\r\n\r\n"
    );
    assert!(exchange(addr, req.as_bytes(), w).await.starts_with("HTTP/1.1 413"));
    // A chunked body over the limit too.
    let chunk = "a".repeat(70_000);
    let req = format!(
        "POST /api/login/begin HTTP/1.1\r\nhost: localhost:8787\r\norigin: {ORIGIN}\r\nx-wicket-csrf: 1\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n{:x}\r\n{chunk}\r\n0\r\n\r\n",
        chunk.len()
    );
    assert!(exchange(addr, req.as_bytes(), w).await.starts_with("HTTP/1.1 413"));
    // Slowloris: a head that never finishes is closed after the header timeout.
    let started = Instant::now();
    let out = exchange(addr, b"GET / HTTP/1.1\r\nhost: local", w).await;
    assert!(started.elapsed() < Duration::from_secs(3), "closed after {:?}: {out}", started.elapsed());
    assert!(!out.contains("200 OK"));
    // A body that never finishes: 408 after the body timeout.
    let req = format!("POST /api/login/begin HTTP/1.1\r\nhost: localhost:8787\r\norigin: {ORIGIN}\r\nx-wicket-csrf: 1\r\ncontent-length: 100\r\n\r\n{{\"a\":");
    let started = Instant::now();
    let out = exchange(addr, req.as_bytes(), w).await;
    assert!(out.starts_with("HTTP/1.1 408") && started.elapsed() < Duration::from_secs(3), "{out}");
}

#[tokio::test]
async fn connections_are_capped_in_all_and_per_client_and_do_not_live_forever() {
    let t = setup("conns");
    let addr = start(t.state, |s| {
        s.limits.max_connections = 3;
        s.limits.per_ip_connections = 2;
        s.limits.conn_lifetime = Duration::from_millis(500);
        s.limits.header_timeout = Duration::from_secs(30);
    })
    .await;
    let get = b"GET / HTTP/1.1\r\nhost: localhost:8787\r\n\r\n";
    // Two idle connections from 127.0.0.1 are allowed; a third from it is closed at once.
    let mut a = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut b = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let out = exchange(addr, get, Duration::from_secs(2)).await;
    assert_eq!(out, "", "over the per-client cap: closed without an answer");
    // The others still work; and a kept-alive connection is closed after its lifetime.
    a.write_all(get).await.unwrap();
    let mut buf = vec![0u8; 4096];
    let n = a.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("HTTP/1.1 200"));
    let started = Instant::now();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), b.read_to_end(&mut rest)).await.expect("closed by the lifetime cap").unwrap();
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(a);
    // Freed slots are reusable.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(exchange(addr, b"GET / HTTP/1.1\r\nhost: localhost:8787\r\nconnection: close\r\n\r\n", Duration::from_secs(2))
        .await
        .starts_with("HTTP/1.1 200"));
}

#[tokio::test]
async fn random_bytes_on_the_wire_never_take_the_server_down() {
    let t = setup("wirefuzz");
    let addr = start(t.state, |s| {
        s.limits.header_timeout = Duration::from_millis(200);
        s.limits.conn_lifetime = Duration::from_secs(1);
        s.limits.per_ip_connections = 64;
    })
    .await;
    let mut rng = Rng(0xfeed_beef_0000_0042);
    let prefixes: [&[u8]; 5] = [
        b"",
        b"GET / HTTP/1.1\r\n",
        b"POST /api/login/finish HTTP/1.1\r\nhost: localhost:8787\r\n",
        b"GET /\x00 HTTP/1.1\r\n",
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    ];
    for _ in 0..150 {
        let mut req = prefixes[rng.below(prefixes.len())].to_vec();
        let n = rng.below(2000);
        req.extend(rng.bytes(n));
        let out = exchange(addr, &req, Duration::from_secs(2)).await;
        assert!(!out.contains("set-cookie"), "{out}");
    }
    assert!(exchange(addr, b"GET / HTTP/1.1\r\nhost: localhost:8787\r\nconnection: close\r\n\r\n", Duration::from_secs(2))
        .await
        .starts_with("HTTP/1.1 200"));
}
