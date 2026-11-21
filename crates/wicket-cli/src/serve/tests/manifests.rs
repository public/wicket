//! The manifest viewer and editor (#172): every field with its defaults marked, validation as
//! `wicket run` does it, the authority diff, and saves and restores as signed, audited, versioned
//! actions (an unsigned or stale one changes nothing).

use super::*;

const BASE: &str = "task: summarise the README\nagent: { name: reader }\nzone:\n  name: docs\n  reach:\n    - { host: api.github.com, methods: [GET], paths: ['/repos/acme/app/**'] }\n  forbid:\n    - { host: api.github.com, paths: ['/repos/acme/app/settings/**'] }\n  inject:\n    - { host: api.github.com, header: authorization, format: 'Bearer {secret}', secret: gh }\n  llm: { max_requests: 10, max_output_tokens: 1000 }\n";

pub(super) fn with_manifest(tag: &str) -> T {
    let mut t = setup(&format!("manifests-{tag}"));
    t.state.vault_dir = t.dir.join("vault");
    let v = wicket_proxy::vault::Vault::new(t.state.vault_dir.clone());
    v.set("gh", "the-real-gh-token").unwrap();
    v.set_hosts("gh", &["api.github.com".into()]).unwrap();
    std::fs::write(t.dir.join("manifests/docs.yaml"), BASE).unwrap();
    t
}

async fn get(t: &T, path: &str) -> (StatusCode, Value, String) {
    let c = format!("__Host-wicket_sid={}", t.sid.clone().unwrap());
    let (s, _, body) = super::http::call(&t.state, "GET", path, &[("cookie", &c)], b"").await;
    (s, serde_json::from_str(&body).unwrap_or(Value::Null), body)
}

#[tokio::test]
async fn a_manifest_shows_every_field_its_defaults_and_its_secrets_by_name() {
    let t = with_manifest("view");
    let (s, v, body) = get(&t, "/api/manifests/manifests/docs.yaml").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["valid"], true);
    assert_eq!(v["writable"], true);
    let field =
        |p: &str| v["fields"].as_array().unwrap().iter().find(|f| f["path"] == p).cloned().unwrap_or_else(|| panic!("no field {p}"));
    assert_eq!(field("task")["default"], false);
    assert_eq!(field("zone.isolation")["default"], true, "not written: the default");
    assert_eq!(field("zone.llm.max_requests")["value"], 10);
    let g = &v["grants"];
    assert_eq!(g["inject"][0]["secret"], "gh");
    assert_eq!(g["inject"][0]["secret_set"], true);
    assert_eq!(g["inject"][0]["bound_to_host"], true);
    assert_eq!(g["hosts"][0]["host"], "api.github.com");
    assert_eq!(g["hosts"][0]["mode"], "inspected", "an injected host is never spliced");
    assert!(!body.contains("the-real-gh-token"), "never a secret's value");
    // Invalid YAML: shown with the error `wicket run` gives.
    std::fs::write(t.dir.join("manifests/bad.yaml"), "task: t\nagent: { name: a }\nzone: { name: z }\n").unwrap();
    let (_, v, _) = get(&t, "/api/manifests/manifests/bad.yaml").await;
    assert_eq!(v["valid"], false);
    assert!(v["error"].as_str().unwrap().contains("llm"), "{v}");
    // Names and roots are checked.
    assert_eq!(get(&t, "/api/manifests/manifests/..%2fledger.db").await.0, StatusCode::NOT_FOUND);
    assert_eq!(get(&t, "/api/manifests/nowhere/docs.yaml").await.0, StatusCode::NOT_FOUND);
}

#[test]
fn the_authority_diff_says_what_changes_and_what_widens() {
    let t = with_manifest("diff");
    let check = |yaml: &str| crate::serve::manifests::check(&crate::serve::manifests::Place::of(&t.state), &json!({ "name": "docs.yaml", "yaml": yaml })).unwrap();
    // A new reach rule: widens.
    let wider =
        BASE.replace("paths: ['/repos/acme/app/**'] }", "paths: ['/repos/acme/app/**'] }\n    - { host: api.example.com, methods: [GET] }");
    let d = check(&wider)["diff"].clone();
    assert_eq!(d["widens"], true, "{d}");
    assert!(
        d["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c.as_str().unwrap().starts_with("+ reach") && c.as_str().unwrap().contains("api.example.com")),
        "{d}"
    );
    // Removing the reach rule: narrower, not wider.
    let narrower = BASE.replace("    - { host: api.github.com, methods: [GET], paths: ['/repos/acme/app/**'] }\n", "");
    let d = check(&narrower)["diff"].clone();
    assert_eq!(d["widens"], false, "{d}");
    assert!(d["changes"].as_array().unwrap().iter().any(|c| c.as_str().unwrap().starts_with("- reach")));
    // A bigger budget, a removed forbid, a new injection: each widens.
    for (what, yaml) in [
        ("budget", BASE.replace("max_requests: 10", "max_requests: 50")),
        ("forbid", BASE.replace("    - { host: api.github.com, paths: ['/repos/acme/app/settings/**'] }\n", "")),
        (
            "inject",
            BASE.replace(
                "secret: gh }",
                "secret: gh }\n    - { host: api.github.com, header: x-extra, format: '{secret}', secret: other }",
            ),
        ),
    ] {
        assert_eq!(check(&yaml)["diff"]["widens"], true, "{what}: {}", check(&yaml)["diff"]);
    }
    // Invalid: the same error `wicket run` gives, and no diff.
    let v = check("task: t\nagent: { name: a }\nzone: { name: z }\n");
    assert_eq!(v["valid"], false);
    assert!(v["diff"].is_null());
}

#[test]
fn a_save_is_signed_audited_and_versioned_and_an_old_version_restores() {
    let mut t = with_manifest("save");
    let path = t.dir.join("manifests/docs.yaml");
    let new = BASE.replace("max_requests: 10", "max_requests: 20");
    // What the passkey signs: the new bytes' hash, the hash they replace, and the authority diff.
    let b = t.begin(json!({ "action": "save_manifest", "name": "docs.yaml", "yaml": new }));
    assert_eq!(b.status, StatusCode::OK, "{:?}", b.body);
    assert_eq!(b.body["action"]["sha256"], crate::serve::manifests::sha256(new.as_bytes()));
    assert_eq!(b.body["action"]["previous_sha256"], crate::serve::manifests::sha256(BASE.as_bytes()));
    assert_eq!(b.body["action"]["widens"], true);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), BASE, "nothing written before it is signed");
    let r = t.act(json!({ "action": "save_manifest", "name": "docs.yaml", "yaml": new }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), new);
    let (kind, body) = t.audit_kinds().pop().unwrap();
    assert_eq!(kind, "manifest.saved");
    assert_eq!((body["name"].as_str(), body["by"].as_str()), (Some("docs.yaml"), Some("passkey:laptop")));
    assert_eq!(crate::verify_signed_decisions(&t.ledger()).unwrap(), (1, 0), "re-verifies offline");
    // The old version is kept, and restores (signed too).
    let hist = t.dir.join("manifests/.history/docs.yaml");
    let old: Vec<String> = std::fs::read_dir(&hist).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    assert_eq!(old.len(), 1);
    assert_eq!(std::fs::read_to_string(hist.join(&old[0])).unwrap(), BASE);
    let r = t.act(json!({ "action": "restore_manifest", "name": "docs.yaml", "version": old[0] }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), BASE);
    assert_eq!(std::fs::read_dir(&hist).unwrap().count(), 2, "the version it replaced is kept as well");
    assert_eq!(crate::verify_signed_decisions(&t.ledger()).unwrap(), (2, 0));
    // A version name can't leave the history.
    assert_eq!(
        t.begin(json!({ "action": "restore_manifest", "name": "docs.yaml", "version": "../../ledger.db" })).status,
        StatusCode::BAD_REQUEST
    );
    // A new manifest is a save too.
    let r = t.act(json!({ "action": "save_manifest", "name": "fresh.yaml", "yaml": BASE }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(std::fs::read_to_string(t.dir.join("manifests/fresh.yaml")).unwrap(), BASE);
}

#[test]
fn an_unsigned_invalid_or_stale_save_changes_nothing() {
    let mut t = with_manifest("refused");
    let path = t.dir.join("manifests/docs.yaml");
    let new = BASE.replace("max_requests: 10", "max_requests: 20");
    // Begun, then finished without a valid signature: refused, nothing written.
    let b = t.begin(json!({ "action": "save_manifest", "name": "docs.yaml", "yaml": new }));
    let ch = b.body["publicKey"]["challenge"].as_str().unwrap().to_string();
    let mut a = t.sign(&ch);
    a["signature"] = json!(b64u(b"not a signature"));
    assert_refused(&t.post("/api/action/finish", a), StatusCode::FORBIDDEN, "signature");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), BASE);
    // Signed out: no session, no save.
    assert_refused(
        &post(&t.state, "/api/action/begin", &anon(), &json!({ "action": "save_manifest", "name": "docs.yaml", "yaml": new })).unwrap(),
        StatusCode::UNAUTHORIZED,
        "sign in",
    );
    // Invalid YAML is refused before anything is signed.
    let r = t.begin(json!({ "action": "save_manifest", "name": "docs.yaml", "yaml": "task: t\nzone: { name: z }\n" }));
    assert_refused(&r, StatusCode::BAD_REQUEST, "doesn't validate");
    // The file changed after it was shown: the signed save doesn't overwrite it.
    let b = t.begin(json!({ "action": "save_manifest", "name": "docs.yaml", "yaml": new }));
    let ch = b.body["publicKey"]["challenge"].as_str().unwrap().to_string();
    std::fs::write(&path, BASE.replace("summarise", "rewrite")).unwrap();
    let a = t.sign(&ch);
    assert_refused(&t.post("/api/action/finish", a), StatusCode::CONFLICT, "changed after you were shown it");
    assert!(std::fs::read_to_string(&path).unwrap().contains("rewrite"));
    assert!(t.audit_kinds().iter().all(|(k, _)| k != "manifest.saved"));
}

/// #713: `wicket manifest` lists, shows, checks, saves and restores through the console's own
/// functions: the same JSON (the fields the CLI reference lists), the same history, and the same
/// `manifest.saved` record, with `via: cli` instead of a signature.
#[test]
fn the_cli_lists_shows_checks_saves_and_restores_as_the_console_does() {
    use crate::cmd::json_tests::documented_as;
    use crate::serve::manifests::{self, Place};
    let t = with_manifest("cli");
    let p = Place::of(&t.state);
    let list = Value::from(manifests::list(p.roots));
    let docs = list.as_array().unwrap().iter().find(|m| m["name"] == "docs.yaml").cloned().unwrap();
    documented_as("`wicket manifest list --json`", &docs);
    assert!(crate::cmd::manifest::line(&docs).starts_with("manifests/docs.yaml  agent reader  zone docs  "), "{docs}");
    let v = manifests::view(&p, "manifests", "docs.yaml").unwrap();
    documented_as("`wicket manifest show --json`", &v);
    let text = crate::cmd::manifest::show_text(&v);
    assert!(text.contains("injects secret gh (set) into authorization on api.github.com"), "{text}");
    assert!(text.contains("host api.github.com: inspected"), "{text}");
    // A check: what the edit adds, and that it widens.
    let wider = BASE.replace("paths: ['/repos/acme/app/**'] }", "paths: ['/repos/acme/app/**'] }\n    - { host: api.example.com, methods: [GET] }");
    let c = manifests::check(&p, &json!({ "name": "docs.yaml", "yaml": wider })).unwrap();
    documented_as("`wicket manifest check --json`", &c);
    let text = crate::cmd::manifest::diff_text(&c["diff"]);
    assert!(text.contains("+ reach") && text.contains("api.example.com") && text.contains("WIDENS"), "{text}");
    // A save: the old version kept, the new one written, the record the console's.
    let l = t.ledger();
    let (save, action) = manifests::prepare(&p, "save_manifest", &json!({ "name": "docs.yaml", "yaml": wider }), "t0").unwrap();
    manifests::save_and_record(&p, &l, &TenantId::single(), &save, &action, "alex@cli", json!({ "via": "cli" })).unwrap();
    assert_eq!(std::fs::read_to_string(t.dir.join("manifests/docs.yaml")).unwrap(), wider);
    let r: Value = serde_json::from_str(&l.audit_latest_unscoped("manifest.saved").unwrap().unwrap()).unwrap();
    assert_eq!((r["action"].as_str(), r["by"].as_str(), r["via"].as_str(), r["widens"].as_bool()), (Some("save_manifest"), Some("alex@cli"), Some("cli"), Some(true)), "{r}");
    assert!(r.get("signed").is_none(), "{r}");
    // Saving the same bytes again changes nothing, and is refused.
    assert!(manifests::prepare(&p, "save_manifest", &json!({ "name": "docs.yaml", "yaml": wider }), "t0").is_err());
    // A restore of the version it replaced: from the history, as a save.
    let v = manifests::view(&p, "manifests", "docs.yaml").unwrap();
    let version = v["history"][0]["version"].as_str().unwrap().to_string();
    let (save, action) = manifests::prepare(&p, "restore_manifest", &json!({ "name": "docs.yaml", "version": version }), "t0").unwrap();
    assert_eq!(action["restored_from"], version.as_str());
    manifests::save_and_record(&p, &l, &TenantId::single(), &save, &action, "alex@cli", json!({ "via": "cli" })).unwrap();
    assert_eq!(std::fs::read_to_string(t.dir.join("manifests/docs.yaml")).unwrap(), BASE);
    assert_eq!(manifests::view(&p, "manifests", "docs.yaml").unwrap()["history"].as_array().map(Vec::len), Some(2));
}
