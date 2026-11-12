//! SymCC's answers on known org policy changes (#51). Needs cvc5: `$CVC5` (or `cvc5` on PATH).
//! Without it the test says so and passes, unless `CVC5_REQUIRED=1` (CI), where it fails.

fn have_cvc5() -> bool {
    let has = std::env::var_os("CVC5").is_some() || std::process::Command::new("cvc5").arg("--version").output().is_ok();
    if !has {
        assert!(std::env::var_os("CVC5_REQUIRED").is_none(), "CVC5_REQUIRED is set, and there is no cvc5");
        eprintln!("no cvc5 ($CVC5): SymCC's fixtures not run here; CI runs them");
    }
    has
}

const V1: &str = r#"
permit(principal, action in [Action::"GET", Action::"HEAD"], resource) when { resource.host like "*.github.com" };
permit(principal, action in [Action::"spawn", Action::"message", Action::"inject"], resource);
forbid(principal, action in [Action::"GET"], resource) when { resource.host == "secrets.github.com" };
"#;

#[tokio::test]
async fn known_changes_are_classified() {
    if !have_cvc5() {
        return;
    }
    let widens =
        |d: &[wicket_policy_diff::ActionDiff]| d.iter().filter(|a| a.widens.is_some()).map(|a| a.action.clone()).collect::<Vec<_>>();
    // The same policy: narrows (keeps).
    assert!(widens(&wicket_policy_diff::diff(V1, V1).await.unwrap()).is_empty());
    // A forbid added: narrows.
    let more_forbids = format!("{V1}\nforbid(principal, action in [Action::\"HEAD\"], resource) when {{ context.risk >= 3 }};");
    assert!(widens(&wicket_policy_diff::diff(V1, &more_forbids).await.unwrap()).is_empty());
    // PUT allowed: widens, on PUT only.
    let put = V1.replace(r#"[Action::"GET", Action::"HEAD"]"#, r#"[Action::"GET", Action::"HEAD", Action::"PUT"]"#);
    assert_eq!(widens(&wicket_policy_diff::diff(V1, &put).await.unwrap()), vec!["PUT".to_string()]);
    // The forbid dropped: widens GET.
    let no_forbid: String = V1.lines().filter(|l| !l.starts_with("forbid")).collect::<Vec<_>>().join("\n");
    assert_eq!(widens(&wicket_policy_diff::diff(V1, &no_forbid).await.unwrap()), vec!["GET".to_string()]);
}
