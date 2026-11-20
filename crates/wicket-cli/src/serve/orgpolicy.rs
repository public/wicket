//! Applying the org policy from the console (#712), beside `wicket policy apply` on the host. The
//! applied policy and its versions are shown by `GET /api/policy` ([`super::authority`]).
//!
//! - **Preview** (`POST /api/policy/preview`, read-only, so the session alone): a pasted or uploaded
//!   policy (Cedar text and its entities JSON) and `keep_runs`, previewed as
//!   `wicket policy apply --dry-run` does ([`wicket_control::policy::preview_in`]): its version
//!   and the one it replaces, what it allows in a line, the zones it doesn't mint for, the running
//!   runs it revokes, and the effect's sha256.
//! - **Apply** (`policy_apply`) is a passkey-signed action. Begin refuses, before a passkey is asked
//!   for: a policy that doesn't parse (400) or doesn't mint (409), and an operator whose
//!   `operators.yaml` authority doesn't cover `policy` at R4 (403). The signed JSON is the preview.
//! - At finish the decision is made on that effect ([`wicket_control::policy::decide`]): a run
//!   that started or ended since, or another apply, makes it stale, and it is refused (audited).
//!   It is audited (`policy.apply_decided`, with the signed assertion) **before** anything is
//!   applied; then `wicket policy apply --decision <seq>` runs on the host's own files, in the
//!   background ([`super::PolicyApplier`]), as root's apply does: it asks every node, checks the
//!   decision again (recent, the same effect, used once), installs, audits `policy.applied`, and
//!   revokes. A failure is audited `policy.apply_failed`; its log is `<data dir>/policy/apply-<seq>.log`.

use super::{err, ok, str_field, Action, Reply, State};
use anyhow::Result;
use http::StatusCode;
use serde_json::{json, Value};
use wicket_control::policy as pol;
use wicket_store::{Ledger, OperatorCredential};

/// The largest policy text or entities the console takes (bytes).
const MAX_POLICY: usize = 256 * 1024;

/// What the console asks the applier to run: `wicket policy apply <cedar> --entities <entities>
/// [--keep-runs] --decision <decision>`, logging to `log`.
pub struct Apply {
    pub cedar: std::path::PathBuf,
    pub entities: std::path::PathBuf,
    pub keep_runs: bool,
    pub decision: i64,
    pub log: std::path::PathBuf,
}

fn input(body: &Value) -> Result<(pol::OrgPolicyText, bool), Reply> {
    let bad = |m: String| err(StatusCode::BAD_REQUEST, m);
    let Some(cedar) = str_field(body, "cedar") else { return Err(bad("cedar required: the org policy's Cedar text".into())) };
    let entities = str_field(body, "entities").unwrap_or("");
    if cedar.len() > MAX_POLICY || entities.len() > MAX_POLICY {
        return Err(bad(format!("an org policy and its entities are at most {} KiB each", MAX_POLICY / 1024)));
    }
    let keep_runs = body.get("keep_runs").and_then(Value::as_bool).unwrap_or(false);
    Ok((pol::OrgPolicyText { cedar: cedar.into(), entities: entities.into() }, keep_runs))
}

fn preview_of(
    state: &State,
    l: &Ledger,
    t: &pol::OrgPolicyText,
    keep_runs: bool,
) -> Result<(wicket_policy::OrgPolicy, pol::Preview), Reply> {
    let org = pol::parse(&t.cedar, &t.entities).map_err(|e| err(StatusCode::BAD_REQUEST, format!("the policy doesn't parse: {e:#}")))?;
    let p = pol::preview_in(&org, &state.data, l, keep_runs).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    Ok((org, p))
}

/// `POST /api/policy/preview`.
pub(super) fn preview(state: &State, body: &Value) -> Reply {
    let l = match state.ledger() {
        Ok(l) => l,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    match input(body).and_then(|(t, keep)| preview_of(state, &l, &t, keep)) {
        Ok((_, p)) => ok(json!({ "preview": p, "dry_run": pol::preview_text(&p) })),
        Err(r) => r,
    }
}

/// `policy_apply`, at begin: what the passkey will sign.
pub(super) fn build(state: &State, l: &Ledger, oc: &OperatorCredential, body: &Value) -> Result<(Action, Value), Reply> {
    let (t, keep_runs) = input(body)?;
    let (_, p) = preview_of(state, l, &t, keep_runs)?;
    if !p.refused.is_empty() {
        return Err(err(
            StatusCode::CONFLICT,
            format!("org policy {} doesn't mint, so it can't be applied: {}", p.version, p.refused.join("; ")),
        ));
    }
    // Told now, before a passkey is asked for; checked again (and a refusal audited) when applied.
    let by = super::fence::human(state, oc).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    pol::may_decide(&by).map_err(|e| err(StatusCode::FORBIDDEN, format!("{e:#}")))?;
    let v = json!({
        "v": 1, "action": "policy_apply", "tenant": state.tenant.0, "version": p.version, "previous": p.previous,
        "already": p.already, "summary": p.summary, "keep_runs": keep_runs, "revokes": p.revokes(), "kept": if keep_runs { p.runs.len() } else { 0 },
        "effect_sha256": p.effect_sha256,
    });
    Ok((Action::PolicyApply(Box::new(PolicyApply { text: t, keep_runs, effect_sha256: p.effect_sha256 })), v))
}

/// A `policy_apply` as checked at begin.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyApply {
    pub text: pol::OrgPolicyText,
    pub keep_runs: bool,
    pub effect_sha256: String,
}

/// `policy_apply`, at finish: decided on the effect signed, audited, then applied in the background.
pub(super) fn apply(state: &State, l: &Ledger, oc: &OperatorCredential, a: &PolicyApply, signed: Value) -> Result<String> {
    let by = super::fence::human(state, oc)?;
    let org = pol::parse(&a.text.cedar, &a.text.entities)?;
    // Staged by its version before it is decided, so the apply reads exactly what was signed.
    let staged = state.data.join("policy").join("staged");
    std::fs::create_dir_all(&staged)?;
    let v = org.version();
    let (cedar, entities) = (staged.join(format!("{v}.cedar")), staged.join(format!("{v}.entities.json")));
    std::fs::write(&cedar, &org.text)?;
    std::fs::write(&entities, &org.entities)?;
    let extra = json!({ "via": "console", "signed": signed });
    let (p, seq) = pol::decide(l, &by, &org, &state.data, a.keep_runs, &a.effect_sha256, extra)?;
    let log = state.data.join("policy").join(format!("apply-{seq}.log"));
    if let Err(e) = (state.policy_applier)(&Apply { cedar, entities, keep_runs: a.keep_runs, decision: seq, log }) {
        let _ = l.audit(&state.tenant, None, "policy.apply_failed", &json!({ "version": v, "decision": seq, "error": format!("{e:#}") }));
        anyhow::bail!("applying org policy {v}: {e:#} (nothing changed)");
    }
    let revokes = p.revokes().len();
    Ok(format!(
        "applying org policy {v} (was {}){}: every node is asked first; the activity log says when it is done (log: policy/apply-{seq}.log; signed with {})",
        p.previous.as_deref().unwrap_or("none"),
        if revokes > 0 { format!(", then {revokes} running run(s) are revoked") } else { String::new() },
        oc.name
    ))
}

/// The real applier: `wicket policy apply … --decision <seq>`, its own process group, logging to
/// its log.
pub(super) fn apply_detached(exe: &std::path::Path, a: &Apply) -> Result<()> {
    use anyhow::Context;
    use std::os::unix::process::CommandExt;
    let out = std::fs::File::create(&a.log).with_context(|| format!("creating {}", a.log.display()))?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["policy", "apply"]).arg(&a.cedar).arg("--entities").arg(&a.entities).arg("--decision").arg(a.decision.to_string());
    if a.keep_runs {
        cmd.arg("--keep-runs");
    }
    let mut child = cmd
        .stdin(std::process::Stdio::null())
        .stdout(out.try_clone()?)
        .stderr(out)
        .process_group(0)
        .spawn()
        .context("starting wicket policy apply")?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}
