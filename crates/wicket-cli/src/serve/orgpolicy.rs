//! Applying the org policy from the console (#712), beside `wicket policy apply` on the host. The
//! applied policy and its versions are shown by `GET /api/policy` ([`super::authority`]).
//!
//! - **Preview** (`POST /api/policy/preview`, read-only, so the session alone): a pasted or uploaded
//!   policy (Cedar text and its entities JSON) and `keep_runs`, previewed as
//!   `wicket policy apply --dry-run` does ([`wicket_control::policy::preview_in`]): its version
//!   and the one it replaces, what it allows in a line, the zones it doesn't mint for, the running
//!   runs it revokes, and the effect's sha256.
//! - **Apply** (`policy_apply`) is a passkey-signed action. Begin refuses, before a passkey is asked
//!   for: no reason (400), an operator whose `operators.yaml` authority doesn't cover `policy` at
//!   R4 (403, before any preview work), and a policy that doesn't parse (400) or doesn't mint (409).
//!   The signed JSON is the preview: the version and the sha256 of its Cedar and entities, what it
//!   changes against the applied policy per zone and group (widens or narrows), what couldn't be
//!   compared, the runs it revokes, and the reason.
//! - A preview mints for every running zone and group, so one runs at a time (429 otherwise), off
//!   the async workers.
//! - At finish the decision is made on that effect ([`wicket_control::policy::decide`]): a run
//!   that started or ended since, or another apply, makes it stale, and it is refused (audited).
//!   It is audited (`policy.apply_decided`, with the signed assertion) **before** anything is
//!   applied; then `wicket policy apply --decision <seq>` runs on the host's own files, in the
//!   background ([`super::PolicyApplier`]), as root's apply does: it asks every node, checks the
//!   decision again (recent, the same effect, used once), installs, audits `policy.applied`, and
//!   revokes. A failure is audited `policy.apply_failed`; its log is `<data dir>/policy/apply-<seq>.log`.

use super::{err, ok, str_field, Action, Reply, State, MAX_REASON};
use anyhow::Result;
use http::StatusCode;
use serde_json::{json, Value};
use wicket_control::policy as pol;
use wicket_store::{Ledger, OperatorCredential};

/// The most policy text and entities the console takes, together (bytes): what fits in a request
/// body ([`super::net::Limits::max_body`], 64 KiB) with its JSON around it. A larger policy is
/// applied on the host.
const MAX_POLICY: usize = 60 * 1024;

/// Runs `f`, compile-and-mint work, off the async workers where the runtime allows (the console's
/// is multi-threaded; tests' isn't).
fn off_workers<T>(f: impl FnOnce() -> T) -> T {
    let multi = tokio::runtime::Handle::try_current().is_ok_and(|h| h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread);
    if multi {
        tokio::task::block_in_place(f)
    } else {
        f()
    }
}

/// [`off_workers`], one unsigned preview at a time on this console (`State::previewing`): each
/// mints for every running zone and group. Err (429) if another runs. A signed apply's finish is
/// never refused for a preview.
fn one_preview<T>(state: &State, f: impl FnOnce() -> T) -> Result<T, Reply> {
    use std::sync::atomic::Ordering;
    if state.previewing.swap(true, Ordering::AcqRel) {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "another org policy preview is running; try again in a moment"));
    }
    struct Done<'a>(&'a std::sync::atomic::AtomicBool);
    impl Drop for Done<'_> {
        fn drop(&mut self) {
            self.0.store(false, std::sync::atomic::Ordering::Release);
        }
    }
    let _done = Done(&state.previewing);
    Ok(off_workers(f))
}

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
    if cedar.len() + entities.len() > MAX_POLICY {
        return Err(bad(format!(
            "an org policy and its entities are at most {} KiB together in the console; apply a larger one on the host",
            MAX_POLICY / 1024
        )));
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
    let p = one_preview(state, || pol::preview_in(&org, &state.data, l, keep_runs))?
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
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
    let reason = str_field(body, "reason").map(str::trim).unwrap_or("");
    if reason.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "say why it is applied: the reason goes on the audit record"));
    }
    if reason.chars().count() > MAX_REASON {
        return Err(err(StatusCode::BAD_REQUEST, "the reason is too long"));
    }
    let (t, keep_runs) = input(body)?;
    // Told now, before any preview work or passkey; checked again (and a refusal audited) when applied.
    let by = super::fence::human(state, oc).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")))?;
    pol::may_decide(&by).map_err(|e| err(StatusCode::FORBIDDEN, format!("{e:#}")))?;
    let (_, p) = preview_of(state, l, &t, keep_runs)?;
    if !p.refused.is_empty() {
        return Err(err(
            StatusCode::CONFLICT,
            format!("org policy {} doesn't mint, so it can't be applied: {}", p.version, p.refused.join("; ")),
        ));
    }
    let v = json!({
        "v": 2, "action": "policy_apply", "tenant": state.tenant.0, "version": p.version, "cedar_sha256": p.cedar_sha256,
        "entities_sha256": p.entities_sha256, "previous": p.previous, "already": p.already, "summary": p.summary,
        "widens": p.widens, "changes": p.changes, "unchecked": p.unchecked, "keep_runs": keep_runs, "revokes": p.revokes(),
        "kept": if keep_runs { p.runs.len() } else { 0 }, "reason": reason, "effect_sha256": p.effect_sha256,
    });
    Ok((Action::PolicyApply(Box::new(PolicyApply { text: t, keep_runs, reason: reason.into(), effect_sha256: p.effect_sha256 })), v))
}

/// A `policy_apply` as checked at begin.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyApply {
    pub text: pol::OrgPolicyText,
    pub keep_runs: bool,
    pub reason: String,
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
    // Each its own, so a failed apply never removes the files of another still waiting to run.
    let tag = super::random_hex(8);
    let (cedar, entities) = (staged.join(format!("{v}-{tag}.cedar")), staged.join(format!("{v}-{tag}.entities.json")));
    std::fs::write(&cedar, &org.text)?;
    std::fs::write(&entities, &org.entities)?;
    let extra = json!({ "via": "console", "why": a.reason, "signed": signed });
    let unstage = || {
        let _ = std::fs::remove_file(&cedar);
        let _ = std::fs::remove_file(&entities);
    };
    let decided = off_workers(|| pol::decide(l, &by, &org, &state.data, a.keep_runs, &a.effect_sha256, extra));
    let (p, seq) = match decided {
        Ok(x) => x,
        Err(e) => {
            unstage();
            return Err(e);
        }
    };
    let log = state.data.join("policy").join(format!("apply-{seq}.log"));
    if let Err(e) =
        (state.policy_applier)(&Apply { cedar: cedar.clone(), entities: entities.clone(), keep_runs: a.keep_runs, decision: seq, log })
    {
        unstage();
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
