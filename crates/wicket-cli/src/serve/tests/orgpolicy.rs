//! Applying the org policy from the console (#712): a preview, then a passkey-signed apply on it.

use super::*;

const ORG: &str = include_str!("../../../../../examples/policy/org.cedar");
const ENTITIES: &str = include_str!("../../../../../examples/policy/org-entities.json");

#[test]
fn an_org_policy_is_previewed_then_applied_with_a_passkey_on_that_preview() {
    let mut t = setup("org-policy");
    let applied = Arc::new(Mutex::new(Vec::new()));
    let rec = applied.clone();
    t.state.policy_applier = Box::new(move |a| {
        rec.lock().unwrap().push((std::fs::read_to_string(&a.cedar).unwrap(), a.keep_runs, a.decision, a.log.clone()));
        Ok(())
    });
    t.running("run_old", "lead");

    // The preview, read-only: what `wicket policy apply --dry-run` prints.
    let r = t.post("/api/policy/preview", json!({ "cedar": "permit(" }));
    assert_refused(&r, StatusCode::BAD_REQUEST, "doesn't parse");
    let r = t.post("/api/policy/preview", json!({ "cedar": ORG, "entities": ENTITIES }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let p = &r.body["preview"];
    assert_eq!((p["previous"].clone(), p["refused"].clone()), (Value::Null, json!([])), "{p}");
    assert_eq!(p["runs"][0]["run"], "run_old");
    assert!(r.body["dry_run"].as_str().unwrap().contains("it revokes 1 running run(s)"), "{:?}", r.body);
    let version = p["version"].as_str().unwrap().to_string();
    assert!(t.audit_kinds().iter().all(|(k, _)| k != "policy.apply_decided"), "a preview decides nothing");

    // Begin: refused before a passkey for a scope without `policy`, and for what doesn't parse.
    let begin = |t: &T| t.begin(json!({ "action": "policy_apply", "cedar": ORG, "entities": ENTITIES, "reason": "quarterly review" }));
    fence::AUTHORITY.with(|a| {
        *a.borrow_mut() =
            Some(crate::operators::Authority::Scoped(crate::operators::Scope { kinds: vec!["http".into()], ..Default::default() }))
    });
    assert_refused(&begin(&t), StatusCode::FORBIDDEN, "may not decide policy");
    fence::AUTHORITY.with(|a| *a.borrow_mut() = None);
    assert_refused(&t.begin(json!({ "action": "policy_apply", "cedar": "nope", "reason": "x" })), StatusCode::BAD_REQUEST, "doesn't parse");
    assert_refused(&t.begin(json!({ "action": "policy_apply", "cedar": ORG })), StatusCode::BAD_REQUEST, "say why");
    let big = "x".repeat(61 * 1024);
    assert_refused(&t.post("/api/policy/preview", json!({ "cedar": big })), StatusCode::BAD_REQUEST, "60 KiB together");

    // A run started between begin and signing: the preview signed is stale, so nothing is applied.
    let b = begin(&t);
    assert_eq!(b.status, StatusCode::OK, "{:?}", b.body);
    assert_eq!(b.body["action"]["version"], version.as_str());
    assert_eq!(b.body["action"]["revokes"][0]["run"], "run_old");
    let a = &b.body["action"];
    assert_eq!(a["cedar_sha256"].as_str().map(str::len), Some(64), "{a}");
    assert_eq!(a["entities_sha256"].as_str().map(str::len), Some(64));
    assert_eq!((a["widens"].as_bool(), a["reason"].as_str()), (Some(false), Some("quarterly review")), "a first policy only narrows: {a}");
    assert!(!a["changes"].as_array().unwrap().is_empty(), "{a}");
    t.running("run_new", "lead");
    let ch = b.body["publicKey"]["challenge"].as_str().unwrap().to_string();
    let signed = t.sign(&ch);
    assert_refused(&t.post("/api/action/finish", signed), StatusCode::CONFLICT, "changed after you were shown it");
    assert!(applied.lock().unwrap().is_empty());

    // Signed on what it does now: decided, audited first, then applied by `wicket policy apply`.
    // A preview running meanwhile refuses another preview, never the signed apply.
    let b = begin(&t);
    assert_eq!(b.status, StatusCode::OK, "{:?}", b.body);
    t.state.previewing.store(true, std::sync::atomic::Ordering::Release);
    assert_refused(&t.post("/api/policy/preview", json!({ "cedar": ORG })), StatusCode::TOO_MANY_REQUESTS, "another org policy preview");
    let ch = b.body["publicKey"]["challenge"].as_str().unwrap().to_string();
    let signed = t.sign(&ch);
    let r = t.post("/api/action/finish", signed);
    assert_eq!(r.status, StatusCode::OK, "a preview never refuses a signed apply: {:?}", r.body);
    t.state.previewing.store(false, std::sync::atomic::Ordering::Release);
    applied.lock().unwrap().clear();
    let r = t.act(json!({ "action": "policy_apply", "cedar": ORG, "entities": ENTITIES, "keep_runs": true, "reason": "quarterly review" }));
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let a = applied.lock().unwrap().clone();
    assert_eq!(a.len(), 1);
    assert_eq!((a[0].0.as_str(), a[0].1), (ORG, true), "the staged file is what was signed");
    let (seq, _, kind, _, body) = t.ledger().audit_tail(1).unwrap().pop().unwrap();
    assert_eq!((seq, kind.as_str()), (a[0].2, "policy.apply_decided"));
    let d: Value = serde_json::from_str(&body).unwrap();
    assert_eq!((d["version"].as_str(), d["keep_runs"].as_bool(), d["via"].as_str()), (Some(version.as_str()), Some(true), Some("console")));
    assert_eq!(
        (d["why"].as_str(), d["cedar_sha256"].clone(), d["widens"].as_bool()),
        (Some("quarterly review"), b.body["action"]["cedar_sha256"].clone(), Some(false))
    );
    assert_eq!(d["revokes"], json!([]), "kept until they end");
    assert!(d["granter_identity"].as_str().unwrap().ends_with("/op/passkey/laptop"), "{d}");
    assert_eq!(a[0].3, t.dir.join("policy").join(format!("apply-{seq}.log")));
    assert_eq!(crate::verify_signed_decisions(&t.ledger()).unwrap(), (2, 0), "both decisions re-verify offline");

    // An apply that can't start is audited, and nothing changed.
    t.state.policy_applier = Box::new(|_| anyhow::bail!("no binary"));
    let r = t.act(json!({ "action": "policy_apply", "cedar": ORG, "entities": ENTITIES, "reason": "quarterly review" }));
    assert_refused(&r, StatusCode::CONFLICT, "no binary");
    assert!(t.audit_kinds().iter().any(|(k, b)| k == "policy.apply_failed" && b["version"] == version.as_str()));
    assert!(!t.dir.join("policy/installed").exists());
    let staged: Vec<_> = std::fs::read_dir(t.dir.join("policy/staged")).unwrap().collect();
    assert_eq!(staged.len(), 4, "the two decided applies keep their files for their applies; the failed one's are removed");
}
