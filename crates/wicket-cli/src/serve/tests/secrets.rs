//! The Secrets card: the vault by name and binding (never a value), and set, hosts and delete as
//! passkey-signed, audited actions. A value goes only in `finish`'s body, hashed with a salt for the
//! signature, and never comes back in a response, a log or the audit.

use super::*;
use std::sync::{Arc, Mutex};

const VALUE: &str = "ghp_the-very-secret-value-0123456789";
const OLD: &str = "ghp_the-old-value-9876543210";
const SALT: &str = "00112233445566778899aabbccddeeff";

const DOCS: &str = "agent: { name: reader }\nzone:\n  name: docs\n  inject:\n    - { host: api.github.com, header: authorization, format: 'Bearer {secret}', secret: gh }\n    - { host: api.example.com, header: x-key, secret: unset-key, optional: true }\n";

fn with_vault(tag: &str) -> T {
    let mut t = setup(&format!("secrets-{tag}"));
    t.state.vault_dir = t.dir.join("vault");
    let v = wicket_proxy::vault::Vault::new(t.state.vault_dir.clone());
    v.set("gh", OLD).unwrap();
    v.set_hosts("gh", &["api.github.com".into()]).unwrap();
    std::fs::write(t.dir.join("manifests/docs.yaml"), DOCS).unwrap();
    t
}

fn vault(t: &T) -> wicket_proxy::vault::Vault {
    wicket_proxy::vault::Vault::new(t.state.vault_dir.clone())
}

/// What the page sends to begin a set: the salted digest, never the value.
fn set_body(name: &str, value: &str, hosts: Value) -> Value {
    json!({ "action": "set_secret", "name": name, "hosts": hosts, "value_salt": SALT, "value_sha256": super::super::secrets::value_digest(SALT, value) })
}

/// Every tracing event while `f` runs, as text.
fn logs() -> (Arc<Mutex<Vec<u8>>>, tracing::subscriber::DefaultGuard) {
    #[derive(Clone)]
    struct W(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for W {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buf = Arc::new(Mutex::new(Vec::new()));
    let w = W(buf.clone());
    let sub = tracing_subscriber::fmt().with_max_level(tracing::Level::TRACE).with_writer(move || w.clone()).finish();
    (buf, tracing::subscriber::set_default(sub))
}

/// Everything the console has recorded or could show: the audit log, the state view.
async fn everything(t: &T) -> String {
    let c = format!("__Host-wicket_sid={}", t.sid.clone().unwrap());
    let (_, _, state) = super::http::call(&t.state, "GET", "/api/state", &[("cookie", &c)], b"").await;
    let audit: Vec<String> = t.ledger().audit_tail(1000).unwrap().into_iter().map(|(_, _, k, _, b)| format!("{k} {b}")).collect();
    format!("{state}\n{}", audit.join("\n"))
}

#[tokio::test]
async fn the_card_lists_secrets_by_name_kind_hosts_and_users_never_a_value() {
    let t = with_vault("view");
    let key = t.dir.join("api-key");
    std::fs::write(&key, "the-linked-file-value").unwrap();
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    vault(&t).link("linked", key.to_str().unwrap(), None, None, None).unwrap();
    t.ledger().run_started(&TenantId::single(), &RunId("run_docs".into()), "docs", "reader").unwrap();
    let all = everything(&t).await;
    for leak in [OLD, "ghp_", "the-linked-file-value"] {
        assert!(!all.contains(leak), "{leak} shown");
    }
    let s = dashboard(&t.state).unwrap();
    let list = s["secrets"]["secrets"].as_array().unwrap();
    let gh = list.iter().find(|x| x["name"] == "gh").unwrap();
    assert_eq!((gh["kind"].as_str(), gh["hosts"].clone()), (Some("value"), json!(["api.github.com"])));
    assert!(gh["set_at"].as_i64().unwrap() > 0);
    assert_eq!(gh["zones"], json!(["docs"]));
    assert_eq!(gh["runs"][0]["run"], "run_docs", "a running run in a zone that uses it");
    let u = &gh["used_by"][0];
    assert_eq!((u["host"].as_str(), u["header"].as_str(), u["format"].as_str()), (Some("api.github.com"), Some("authorization"), Some("Bearer {secret}")));
    let l = list.iter().find(|x| x["name"] == "linked").unwrap();
    assert_eq!(l["kind"], "reference");
    assert!(l["hosts"].as_array().unwrap().is_empty());
    assert_eq!(s["secrets"]["missing"][0]["name"], "unset-key", "a name a manifest uses that the vault lacks");
    assert!(s["secrets"]["link_cli_only"].as_str().unwrap().contains("wicket secret link"));
    // Only fields the card names: nothing else of a secret's record reaches the page.
    let keys: Vec<&String> = gh.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["hosts", "kind", "name", "reference", "runs", "set_at", "used_by", "zones"]);
}

#[tokio::test]
async fn an_unsigned_or_badly_signed_set_is_refused_and_audited_and_changes_nothing() {
    let mut t = with_vault("unsigned");
    let (logged, _g) = logs();
    // A session alone: every /api/secrets/* is refused, and audited by name, never the value.
    let sid = t.sid.clone();
    for p in ["/api/secrets/set", "/api/secrets/hosts", "/api/secrets/delete"] {
        let (s, _, body) =
            super::http::post_json(&t.state, p, sid.as_deref(), &json!({ "name": "gh", "value": VALUE, "hosts": ["evil.example"] })).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{p}: {body}");
        assert!(body.contains("signed action") && !body.contains(VALUE), "{body}");
    }
    let refused: Vec<Value> = t.audit_kinds().into_iter().filter(|(k, _)| k == "secret.refused").map(|(_, b)| b).collect();
    assert_eq!(refused.len(), 3);
    assert!(refused.iter().all(|r| r["name"] == "gh" && r["reason"].as_str().unwrap().contains("unsigned")), "{refused:?}");
    // Signed out: nothing at all.
    let (s, _, _) = super::http::post_json(&t.state, "/api/secrets/set", None, &json!({ "name": "gh", "value": VALUE })).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // The value never goes with begin (it would sit with the pending challenge).
    let mut with_value = set_body("gh", VALUE, json!([]));
    with_value["value"] = VALUE.into();
    let r = t.begin(with_value);
    assert_refused(&r, StatusCode::BAD_REQUEST, "never with begin");
    assert!(!r.body.to_string().contains(VALUE));
    // A bad signature: refused, audited by name, nothing stored.
    let b = t.begin(set_body("gh", VALUE, json!([])));
    assert_eq!(b.status, StatusCode::OK, "{:?}", b.body);
    let ch = b.body["publicKey"]["challenge"].as_str().unwrap().to_string();
    let mut a = t.sign(&ch);
    a["signature"] = b64u(b"not a signature").into();
    a["value"] = VALUE.into();
    let (s, _, body) = super::http::post_json(&t.state, "/api/action/finish", sid.as_deref(), &a).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    let last = t.audit_kinds().into_iter().rev().find(|(k, _)| k == "secret.refused").unwrap().1;
    assert!(last["reason"].as_str().unwrap().contains("signature"), "{last}");
    assert_eq!(vault(&t).get("gh").unwrap(), OLD, "nothing changed");
    // A signed finish whose value isn't the one signed for stores nothing.
    let b = t.begin(set_body("gh", VALUE, json!([])));
    let mut a = t.sign(b.body["publicKey"]["challenge"].as_str().unwrap());
    a["value"] = "some-other-value".into();
    let (s, _, body) = super::http::post_json(&t.state, "/api/action/finish", sid.as_deref(), &a).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert!(body.contains("not the one you signed"), "{body}");
    assert_eq!(vault(&t).get("gh").unwrap(), OLD);
    let all = everything(&t).await;
    assert!(!all.contains(VALUE) && !all.contains("some-other-value"));
    let logged = String::from_utf8(logged.lock().unwrap().clone()).unwrap();
    assert!(!logged.contains(VALUE), "logged: {logged}");
}

#[tokio::test]
async fn a_signed_set_stores_the_value_which_never_appears_in_a_response_log_or_audit() {
    let mut t = with_vault("set");
    let (logged, _g) = logs();
    let sid = t.sid.clone();
    let mut replies = vec![];
    // Replace gh's value (its hosts kept), then store a new secret with hosts.
    for (name, value, hosts) in [("gh", VALUE, json!([])), ("new-key", "nk-second-secret-value", json!(["API.example.com."]))] {
        let (s, _, body) = super::http::post_json(&t.state, "/api/action/begin", sid.as_deref(), &set_body(name, value, hosts)).await;
        assert_eq!(s, StatusCode::OK, "{body}");
        let b: Value = serde_json::from_str(&body).unwrap();
        let signed = &b["action"];
        assert_eq!(signed["action"], "set_secret");
        assert_eq!(signed["value_sha256"], super::super::secrets::value_digest(SALT, value), "the passkey signs the salted digest");
        assert!(!body.contains(value));
        let mut a = t.sign(b["publicKey"]["challenge"].as_str().unwrap());
        a["value"] = value.into();
        let (s, _, body) = super::http::post_json(&t.state, "/api/action/finish", sid.as_deref(), &a).await;
        assert_eq!(s, StatusCode::OK, "{body}");
        replies.push(body);
    }
    assert!(replies[0].contains("replaced the value of secret gh; sent only to api.github.com"), "{}", replies[0]);
    assert!(replies[1].contains("stored secret new-key; sent only to api.example.com"), "{}", replies[1]);
    let v = vault(&t);
    assert_eq!(v.get("gh").unwrap(), VALUE, "new values are read at the next use");
    assert_eq!(v.hosts("gh"), ["api.github.com"]);
    assert_eq!(v.get_for("new-key", "api.example.com").unwrap(), "nk-second-secret-value");
    let sets: Vec<Value> = t.audit_kinds().into_iter().filter(|(k, _)| k == "secret.set").map(|(_, b)| b).collect();
    assert_eq!(sets.len(), 2);
    assert_eq!((sets[0]["name"].as_str(), sets[0]["replaced"].as_bool()), (Some("gh"), Some(true)));
    assert!(sets[0]["signed"]["signature"].is_string(), "the signed record is kept, for audit --verify");
    let all = everything(&t).await;
    for value in [VALUE, "nk-second-secret-value"] {
        assert!(!all.contains(value), "{value} in a view or the audit");
        assert!(replies.iter().all(|r| !r.contains(value)));
    }
    let logged = String::from_utf8(logged.lock().unwrap().clone()).unwrap();
    assert!(!logged.contains(VALUE) && !logged.contains("nk-second"), "logged: {logged}");
    // A link can't be made here, and a reference can't be overwritten with a value.
    let r = t.begin(json!({ "action": "set_secret", "name": "x", "file": "/etc/passwd" }));
    assert_refused(&r, StatusCode::BAD_REQUEST, "wicket secret link");
    let key = t.dir.join("k");
    std::fs::write(&key, "k").unwrap();
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    v.link("linked", key.to_str().unwrap(), None, None, None).unwrap();
    assert_refused(&t.begin(set_body("linked", VALUE, json!([]))), StatusCode::CONFLICT, "reference");
    // A value with a line break would split a header: refused.
    let b = t.begin(set_body("gh", "a\r\nX-Evil: 1", json!([])));
    let mut a = t.sign(b.body["publicKey"]["challenge"].as_str().unwrap());
    a["value"] = "a\r\nX-Evil: 1".into();
    assert_refused(&t.post("/api/action/finish", a), StatusCode::CONFLICT, "control character");
    assert_eq!(v.get("gh").unwrap(), VALUE);
}

#[tokio::test]
async fn hosts_change_as_signed_and_a_stale_change_is_refused() {
    let mut t = with_vault("hosts");
    let r = t.act(json!({ "action": "secret_hosts", "name": "gh", "hosts": "api.github.com, *.githubusercontent.com" }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let v = vault(&t);
    assert_eq!(v.hosts("gh"), ["api.github.com", "*.githubusercontent.com"]);
    assert!(v.get_for("gh", "raw.githubusercontent.com").is_ok() && v.get_for("gh", "evil.example").is_err());
    let rec = t.audit_kinds().into_iter().find(|(k, _)| k == "secret.hosts").unwrap().1;
    assert_eq!(rec["previous_hosts"], json!(["api.github.com"]));
    // Bad patterns and an empty list are refused, as by `wicket secret hosts`.
    assert_refused(&t.begin(json!({ "action": "secret_hosts", "name": "gh", "hosts": ["*"] })), StatusCode::BAD_REQUEST, "not a host");
    assert_refused(&t.begin(json!({ "action": "secret_hosts", "name": "gh", "hosts": [] })), StatusCode::BAD_REQUEST, "hosts required");
    assert_refused(&t.begin(json!({ "action": "secret_hosts", "name": "nope", "hosts": ["a.example"] })), StatusCode::NOT_FOUND, "no secret");
    // Rebound on the host between begin and finish: what was signed is no longer what it replaces.
    let b = t.begin(json!({ "action": "secret_hosts", "name": "gh", "hosts": ["evil.example"] }));
    v.set_hosts("gh", &["api.github.com".into()]).unwrap();
    let a = t.sign(b.body["publicKey"]["challenge"].as_str().unwrap());
    assert_refused(&t.post("/api/action/finish", a), StatusCode::CONFLICT, "changed after you were shown it");
    assert_eq!(v.hosts("gh"), ["api.github.com"]);
    // A reference's hosts can be changed here.
    let key = t.dir.join("k");
    std::fs::write(&key, "k").unwrap();
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    v.link("linked", key.to_str().unwrap(), None, None, None).unwrap();
    assert_eq!(t.act(json!({ "action": "secret_hosts", "name": "linked", "hosts": ["api.example.com"] })).status, StatusCode::OK);
    assert_eq!(v.hosts("linked"), ["api.example.com"]);
}

#[tokio::test]
async fn delete_names_the_zones_and_runs_using_it_and_removes_it_when_signed() {
    let mut t = with_vault("delete");
    t.ledger().run_started(&TenantId::single(), &RunId("run_docs".into()), "docs", "reader").unwrap();
    let b = t.begin(json!({ "action": "delete_secret", "name": "gh" }));
    assert_eq!(b.status, StatusCode::OK, "{:?}", b.body);
    assert_eq!(b.body["action"]["zones"], json!(["docs"]), "the passkey signs who it leaves without");
    assert_eq!(b.body["action"]["runs"], json!(["run_docs"]));
    let a = t.sign(b.body["publicKey"]["challenge"].as_str().unwrap());
    let r = t.post("/api/action/finish", a);
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let v = vault(&t);
    assert!(!v.has("gh") && v.hosts("gh").is_empty());
    let rec = t.audit_kinds().into_iter().find(|(k, _)| k == "secret.removed").unwrap().1;
    assert_eq!((rec["name"].as_str(), rec["via"].as_str()), (Some("gh"), Some("console")));
    assert!(!everything(&t).await.contains(OLD));
    assert_refused(&t.begin(json!({ "action": "delete_secret", "name": "gh" })), StatusCode::NOT_FOUND, "no secret");
    assert_refused(&t.begin(json!({ "action": "delete_secret", "name": "../etc" })), StatusCode::BAD_REQUEST, "secret name");
}
