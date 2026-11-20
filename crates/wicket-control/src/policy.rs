//! `wicket policy` (#51): the installation's org policy in Cedar, and each zone's.
//!
//! The org policy is `<data dir>/policy/org.cedar`, with the groups zones are in in
//! `org-entities.json` (Cedar entities JSON). `wicket policy apply` installs it and records its
//! version in `policy/installed`; from then on a missing or changed `org.cedar` refuses every mint
//! (a deleted file must not silently remove the ceiling, nor a hand edit bypass `apply`). With no
//! policy ever applied, tokens carry no org layer.
//!
//! Every token is compiled at mint from the policy current then, and records its version (block 0's
//! `policy` fact, and the run's ledger row). `apply` checks first that the new version compiles and
//! mints a token that loads for every running run's zone, and that every node talks a protocol that
//! reads it; then it installs it and revokes the runs minted under older versions. Every version is
//! kept in `policy/versions/`, so a re-attached run is minted under its own.

use crate::{data_dir, ledger_path};
use anyhow::{bail, Context, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use wicket_policy::{MintCtx, OrgPolicy};

fn dir() -> PathBuf {
    data_dir().join("policy")
}

fn installed() -> Option<String> {
    installed_in(&dir())
}

/// The applied org policy's version in a policy directory (`<data dir>/policy`), if one was applied.
pub fn installed_in(dir: &Path) -> Option<String> {
    std::fs::read_to_string(dir.join("installed")).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// The groups zones are in, as Cedar entities JSON, from a policy directory: its
/// `org-entities.json`, or none (`[]`) without one. The one reader of that file.
pub fn entities_in(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("org-entities.json")).unwrap_or_else(|_| "[]".into())
}

/// The installation's org policy, if one was applied. Refused if it isn't what was applied.
pub fn org() -> Result<Option<OrgPolicy>> {
    let p = dir().join("org.cedar");
    let want = installed();
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => match want {
            None => return Ok(None),
            Some(v) => bail!("the org policy {v} was applied, but {} is gone: apply it again (`wicket policy apply`)", p.display()),
        },
        Err(e) => return Err(e).with_context(|| p.display().to_string()),
    };
    let o = OrgPolicy::parse(&text, &entities_in(&dir())).with_context(|| p.display().to_string())?;
    match want {
        Some(v) if v == o.version() => Ok(Some(o)),
        Some(v) => bail!(
            "{} is version {}, not the applied {v}: it was changed by hand; apply it (`wicket policy apply`) to make it the installation's",
            p.display(),
            o.version()
        ),
        None => bail!("{} exists but was never applied: apply it (`wicket policy apply`)", p.display()),
    }
}

/// A version kept by `apply` (for a run minted under it).
pub fn version(v: &str) -> Result<Option<OrgPolicy>> {
    if !v.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("policy version {v:?}");
    }
    let d = dir().join("versions");
    let Ok(text) = std::fs::read_to_string(d.join(format!("{v}.cedar"))) else { return Ok(None) };
    let ents = std::fs::read_to_string(d.join(format!("{v}.entities.json"))).unwrap_or_else(|_| "[]".into());
    let o = OrgPolicy::parse(&text, &ents)?;
    if o.version() != v {
        bail!("the kept policy {v} hashes to {}", o.version());
    }
    Ok(Some(o))
}

/// The org policy a run's token is minted under: for a re-attached run, the version its first
/// supervisor minted it under (`--keep-runs` holds across a control-host restart); else the
/// installation's.
pub fn for_run(run: &str, attach: bool) -> Result<Option<OrgPolicy>> {
    if attach {
        let recorded = wicket_store::Ledger::open(&ledger_path())?.run_policy(run)?;
        return match recorded {
            None => Ok(None),
            Some(v) => version(&v)?.map(Some).with_context(|| format!("run {run} was minted under org policy {v}, which isn't kept here")),
        };
    }
    org()
}

/// What a box is at mint, for its org layer.
pub fn mint_ctx(org: &OrgPolicy, zone: &str, tenant: &str, principal: &str, depth: i64) -> MintCtx {
    MintCtx { zone: zone.into(), tenant: tenant.into(), principal: principal.into(), depth, groups: org.groups_of(zone) }
}

fn load(file: &Path, entities: Option<&Path>) -> Result<OrgPolicy> {
    let text = std::fs::read_to_string(file).with_context(|| file.display().to_string())?;
    let ents = match entities {
        Some(e) => std::fs::read_to_string(e).with_context(|| e.display().to_string())?,
        None => "[]".into(),
    };
    OrgPolicy::parse(&text, &ents).with_context(|| file.display().to_string())
}

/// An org policy's Cedar text and entities JSON, as the console was given them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrgPolicyText {
    pub cedar: String,
    pub entities: String,
}

/// An org policy from its Cedar text and its entities JSON (empty: none), as the console takes it.
pub fn parse(text: &str, entities: &str) -> Result<OrgPolicy> {
    let ents = if entities.trim().is_empty() { "[]" } else { entities };
    Ok(OrgPolicy::parse(text, ents)?)
}

/// A running run an apply would revoke (or, with `--keep-runs`, leave on its policy until it ends).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RunChange {
    pub run: String,
    pub zone: String,
    /// The version it was minted under (None: no org policy).
    pub policy: Option<String>,
}

/// What applying an org policy would do (#712): `wicket policy apply --dry-run` prints it, and the
/// console shows it and signs its effect. Nothing here writes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Preview {
    pub version: String,
    /// The applied version now (None: none ever applied).
    pub previous: Option<String>,
    /// It is the applied version already.
    pub already: bool,
    /// What its compiled layer holds, in a line.
    pub summary: String,
    /// The zones it doesn't mint for: while there are any, applying it changes nothing.
    pub refused: Vec<String>,
    /// The running runs minted under another version.
    pub runs: Vec<RunChange>,
    pub keep_runs: bool,
    /// What the human decides on: the version, the one it replaces, and which runs it revokes.
    pub effect_sha256: String,
}

impl Preview {
    /// The runs it revokes: none with `keep_runs`.
    pub fn revokes(&self) -> Vec<&RunChange> {
        if self.keep_runs {
            vec![]
        } else {
            self.runs.iter().collect()
        }
    }
}

/// [`Preview`] of `org` against the installation in `data` (its `policy/` and its runs' records) and
/// its ledger `l`.
pub fn preview_in(org: &OrgPolicy, data: &Path, l: &wicket_store::Ledger, keep_runs: bool) -> Result<Preview> {
    use sha2::Digest;
    let version = org.version();
    let pdir = data.join("policy");
    let previous = installed_in(&pdir);
    let already = previous.as_deref() == Some(version.as_str()) && pdir.join("org.cedar").exists();
    let mut runs = vec![];
    for (run, zone, pv) in l.running_policies()? {
        if pv.as_deref() == Some(version.as_str()) || l.identity(&run)?.is_none() {
            continue;
        }
        runs.push(RunChange { run, zone, policy: pv });
    }
    let revoked: Vec<&str> = if keep_runs { vec![] } else { runs.iter().map(|r| r.run.as_str()).collect() };
    let effect = serde_json::json!({ "v": 1, "kind": "policy_apply", "version": version, "previous": previous,
                                     "keep_runs": keep_runs, "revokes": revoked });
    Ok(Preview {
        summary: summary(org)?,
        refused: trial_in(org, data, Some(l)),
        effect_sha256: hex::encode(sha2::Sha256::digest(effect.to_string().as_bytes())),
        version,
        previous,
        already,
        runs,
        keep_runs,
    })
}

/// A preview as text: what `--dry-run` prints.
pub fn preview_text(p: &Preview) -> String {
    let mut o = format!("org policy {} (now {})\n  {}\n", p.version, p.previous.as_deref().unwrap_or("none"), p.summary);
    if p.already {
        o.push_str("  it is the installation's already\n");
    }
    if !p.refused.is_empty() {
        o.push_str(&format!("  it doesn't mint, so applying it would change nothing:\n    - {}\n", p.refused.join("\n    - ")));
    }
    match (p.runs.is_empty(), p.keep_runs) {
        (true, _) => o.push_str("  no running run is minted under another version\n"),
        (false, true) => o.push_str(&format!("  {} running run(s) keep their policy until they end (--keep-runs)\n", p.runs.len())),
        (false, false) => {
            o.push_str(&format!("  it revokes {} running run(s), minted under another version (their boxes stop):\n", p.runs.len()));
            for r in &p.runs {
                o.push_str(&format!("    {}  zone {}  policy {}\n", r.run, r.zone, r.policy.as_deref().unwrap_or("none")));
            }
        }
    }
    o.push_str(&format!("  effect {}\n", p.effect_sha256));
    o
}

/// The risk applying an org policy is decided at: it changes what every box may do, and revokes runs.
pub const RISK: i64 = 4;

/// Whether `by` may apply an org policy from the console: a human whose authority covers `policy` at R4.
pub fn may_decide(by: &crate::grant::Granter) -> Result<crate::operators::Operator> {
    let crate::grant::Granter::Human(o) = by else { bail!("an org policy is applied by a human operator, not {}", by.label()) };
    o.may_decide(&crate::operators::Asked { kind: "policy".into(), host: String::new(), risk: Some(RISK) }).map_err(anyhow::Error::msg)?;
    Ok(o.clone())
}

/// A console decision to apply `org` (#712) as `by`, on the effect `shown`, against the installation
/// in `data`: only a human [`may_decide`] covers, only a policy that mints, and only if applying it
/// still does what was shown. A refusal is audited (`decision.refused`). The decision is audited
/// (`policy.apply_decided`, with `extra`) before anything is applied; the apply it starts
/// (`wicket policy apply --decision`) checks it. Returns the preview and the decision's sequence.
pub fn decide(
    l: &wicket_store::Ledger,
    by: &crate::grant::Granter,
    org: &OrgPolicy,
    data: &Path,
    keep_runs: bool,
    shown: &str,
    extra: serde_json::Value,
) -> Result<(Preview, i64)> {
    let refused = |why: anyhow::Error| {
        let rec = serde_json::json!({ "target": org.version(), "decision": "policy_apply", "by": by.label(), "why": format!("{why:#}") });
        match l.audit(&wicket_core::TenantId::single(), None, "decision.refused", &rec) {
            Ok(_) => why.context("refused (the refusal is on the audit record)"),
            Err(e) => why.context(format!("refused (the refusal could not be recorded: {e})")),
        }
    };
    let o = may_decide(by).map_err(refused)?;
    let pre = preview_in(org, data, l, keep_runs)?;
    if !pre.refused.is_empty() {
        return Err(refused(anyhow::anyhow!("org policy {} doesn't mint: {}", pre.version, pre.refused.join("; "))));
    }
    if pre.effect_sha256 != shown {
        return Err(refused(anyhow::anyhow!(
            "what applying it does changed after you were shown it (the runs it revokes, or the applied version): look again"
        )));
    }
    let mut rec = serde_json::json!({
        "action": "policy_apply", "version": pre.version, "previous": pre.previous, "keep_runs": keep_runs,
        "revokes": pre.revokes(), "effect_sha256": pre.effect_sha256,
        "by": o.label, "granter": "human", "granter_identity": o.id,
    });
    if let (Some(r), serde_json::Value::Object(x)) = (rec.as_object_mut(), extra) {
        r.extend(x);
    }
    let seq = l
        .audit(&wicket_core::TenantId::single(), None, "policy.apply_decided", &rec)
        .context("the decision could not be recorded in the audit log, so nothing was applied")?;
    Ok((pre, seq))
}

/// How long a console decision to apply a policy may wait for its apply (s).
pub const DECISION_TTL_SECS: i64 = 600;

/// The console's decision `seq` to apply what `p` previews (`policy.apply_decided`), checked by the
/// apply it started: that record, recent, for this version and `--keep-runs`, on this effect, and
/// not used before. Returns who decided it.
fn decided(l: &wicket_store::Ledger, seq: i64, p: &Preview) -> Result<String> {
    let r = l
        .audit_record_at(seq)?
        .filter(|r| r.kind == "policy.apply_decided")
        .with_context(|| format!("no decision {seq} to apply a policy"))?;
    let b: serde_json::Value = serde_json::from_str(&r.body)?;
    if b["version"].as_str() != Some(p.version.as_str()) || b["keep_runs"].as_bool() != Some(p.keep_runs) {
        bail!("decision {seq} is for another policy or --keep-runs");
    }
    if wicket_store::now() - r.ts > DECISION_TTL_SECS {
        bail!("decision {seq} is older than {} minutes: decide again", DECISION_TTL_SECS / 60);
    }
    for kind in ["policy.applied", "policy.apply_failed"] {
        if l.audit_of_kind(kind)?
            .iter()
            .any(|x| serde_json::from_str::<serde_json::Value>(&x.body).is_ok_and(|v| v["decision"].as_i64() == Some(seq)))
        {
            bail!("decision {seq} was used already");
        }
    }
    if b["effect_sha256"].as_str() != Some(p.effect_sha256.as_str()) {
        bail!("what applying it does changed since it was decided (the runs it revokes, or the applied version): decide again");
    }
    Ok(b["by"].as_str().unwrap_or("console").to_string())
}

/// A token minted for `zone` under `org`, then loaded as a node would: what minting would refuse
/// (the node's structural caps: alternatives, regexes, token size) shows here.
fn mints(org: &OrgPolicy, zone: &wicket_core::ZoneSpec, groups: BTreeSet<String>) -> Result<()> {
    let mint = MintCtx { zone: zone.name.clone(), tenant: "t".into(), principal: "human:check".into(), depth: 0, groups };
    let layer = org.layer(&mint)?;
    let key = wicket_authz::SigningKey::generate();
    let c = wicket_policy::ceiling(zone, "run_check", 4_102_444_800, vec![key.public()], &["img:check".into()], Some(layer))?;
    let t = wicket_authz::mint(&key, "t", "human:check", &c)?;
    wicket_authz::load(&t.to_bytes()?, &key.public(), &|_| false).map_err(|e| anyhow::anyhow!("a node would refuse its token: {e}"))?;
    Ok(())
}

/// The zones the check mints for: every running run's (from its record under `data`), and a bare one.
fn zones_to_check(data: &Path, l: Option<&wicket_store::Ledger>) -> Vec<(String, wicket_core::ZoneSpec)> {
    let bare: wicket_core::ZoneSpec = wicket_core::yaml::from_str("name: policy-check\n").expect("a bare zone");
    let mut out = vec![("a zone with no rules".to_string(), bare)];
    let opened = if l.is_none() { wicket_store::Ledger::open(&ledger_path()).ok() } else { None };
    if let Some(l) = l.or(opened.as_ref()) {
        for (run, _, _) in l.running_policies().unwrap_or_default() {
            let rec = data.join("runs").join(&run).join("ctl/run.json");
            let m = std::fs::read(&rec)
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|v| v["manifest"].as_str().and_then(|y| wicket_agent::load(y).ok()));
            if let Some(m) = m {
                out.push((format!("run {run}'s zone {}", m.zone.name), m.zone));
            }
        }
    }
    out
}

/// Compiles and mints `org` for each zone to check, as a member of no group, of every group, and of
/// each group alone. Returns what failed.
fn trial(org: &OrgPolicy) -> Vec<String> {
    trial_in(org, &data_dir(), None)
}

/// [`trial`] against the installation in `data` and its ledger (None: the installation's).
fn trial_in(org: &OrgPolicy, data: &Path, l: Option<&wicket_store::Ledger>) -> Vec<String> {
    let all: BTreeSet<String> = org
        .entities()
        .iter()
        .filter(|e| e.uid().type_name().to_string() == "Group")
        .map(|e| e.uid().id().unescaped().to_string())
        .collect();
    let mut sets = vec![BTreeSet::new(), all.clone()];
    sets.extend(all.iter().map(|g| BTreeSet::from([g.clone()])));
    let mut bad = vec![];
    for (what, z) in zones_to_check(data, l) {
        let mut ss = sets.clone();
        ss.push(org.groups_of(&z.name));
        for groups in ss {
            if let Err(e) = mints(org, &z, groups.clone()) {
                bad.push(format!("{what} (groups {groups:?}): {e:#}"));
                break;
            }
        }
    }
    bad
}

/// What a compiled org layer holds, in a line.
fn summary(org: &OrgPolicy) -> Result<String> {
    let m = mint_ctx(org, "(any zone)", "", "", 0);
    let l = org.layer(&m)?;
    let opt = |o: Option<usize>| o.map(|n| format!("{n} permit(s)")).unwrap_or_else(|| "unconstrained".into());
    Ok(format!(
        "HTTP {}, {} forbid(s); spawn {}; messages {}; injections {} (for a zone in no group)",
        opt(l.http.as_ref().map(Vec::len)),
        l.forbid.len(),
        opt(l.spawn.as_ref().map(Vec::len)),
        opt(l.msg_from.as_ref().map(Vec::len)),
        opt(l.inject.as_ref().map(Vec::len)),
    ))
}

/// `wicket policy check FILE [--entities F]`.
pub fn check(file: &Path, entities: Option<&Path>) -> Result<()> {
    let p = load(file, entities)?;
    let bad = trial(&p);
    if !bad.is_empty() {
        bail!("{}: version {} doesn't mint:\n  - {}", file.display(), p.version(), bad.join("\n  - "));
    }
    println!("{}: version {}, validates against wicket's schema, compiles and mints", file.display(), p.version());
    println!("  {}", summary(&p)?);
    Ok(())
}

/// `wicket policy show`.
pub fn show() -> Result<()> {
    let cur = org();
    match &cur {
        Ok(Some(p)) => {
            println!("org policy {} ({})", p.version(), dir().join("org.cedar").display());
            println!("  {}", summary(p)?);
        }
        Ok(None) => println!("no org policy ({} doesn't exist): tokens carry zone policy only", dir().join("org.cedar").display()),
        Err(e) => println!("the org policy can't be used, and every mint is refused: {e:#}"),
    }
    let l = wicket_store::Ledger::open(&ledger_path())?;
    let want = cur.ok().flatten().map(|p| p.version());
    let runs = l.running_policies()?;
    let old: Vec<_> = runs.iter().filter(|(_, _, v)| *v != want).collect();
    println!("{} running run(s), {} minted under another version", runs.len(), old.len());
    for (run, zone, v) in old {
        println!("  {run}  zone {zone}  policy {}", v.as_deref().unwrap_or("(none)"));
    }
    Ok(())
}

fn write_replace(p: &Path, body: &str) -> Result<()> {
    Ok(wicket_chan::files::replace(p, "new", body.as_bytes())?)
}

/// `wicket policy apply FILE [--entities F] [--keep-runs] [--dry-run]`. With `decision` (the
/// console's, #712), only what that signed decision previewed is applied, once, and an apply that
/// fails is audited (`policy.apply_failed`).
pub async fn apply(file: &Path, entities: Option<&Path>, keep_runs: bool, dry_run: bool, decision: Option<i64>) -> Result<()> {
    let p = load(file, entities)?;
    let l = wicket_store::Ledger::open(&ledger_path())?;
    let pre = preview_in(&p, &data_dir(), &l, keep_runs)?;
    if dry_run {
        print!("{}", preview_text(&pre));
        return Ok(());
    }
    let Some(seq) = decision else { return install(&p, &pre, &crate::operator(), None).await };
    let r = match decided(&l, seq, &pre) {
        Ok(by) => install(&p, &pre, &by, Some(seq)).await,
        Err(e) => Err(e),
    };
    if let Err(e) = &r {
        let _ = l.audit(
            &wicket_core::TenantId::single(),
            None,
            "policy.apply_failed",
            &serde_json::json!({ "version": pre.version, "decision": seq, "error": format!("{e:#}") }),
        );
    }
    r
}

/// Installs `p`, previewed as `pre`, as `by`, and revokes the runs minted under another version
/// unless `pre.keep_runs`.
async fn install(p: &OrgPolicy, pre: &Preview, by: &str, decision: Option<i64>) -> Result<()> {
    let v = p.version();
    // Nothing changes unless it mints for every running run's zone, and every node reads it.
    if !pre.refused.is_empty() {
        bail!("org policy {v} doesn't mint, so nothing changed:\n  - {}", pre.refused.join("\n  - "));
    }
    let lacking = crate::roots::nodes_unreachable().await?;
    if !lacking.is_empty() {
        bail!(
            "not every node can read tokens with an org layer; nothing changed:\n{}\n(update them, or revoke the ones you no longer use)",
            lacking.iter().map(|(n, why)| format!("  - node {n}: {why}")).collect::<Vec<_>>().join("\n")
        );
    }
    let l = wicket_store::Ledger::open(&ledger_path())?;
    // A decided apply is of what was shown: the runs it revokes are checked again after the nodes'.
    if decision.is_some() && preview_in(p, &data_dir(), &l, pre.keep_runs)?.effect_sha256 != pre.effect_sha256 {
        bail!("what applying it does changed while the nodes were asked (a run started or ended): decide again");
    }
    let prev = installed();
    if pre.already && prev.as_deref() == Some(v.as_str()) {
        println!("org policy {v} is already the installation's");
    } else {
        let d = dir();
        std::fs::create_dir_all(d.join("versions"))?;
        // Every version is kept, by its hash, for review and for runs minted under it.
        std::fs::write(d.join("versions").join(format!("{v}.cedar")), &p.text)?;
        std::fs::write(d.join("versions").join(format!("{v}.entities.json")), &p.entities)?;
        write_replace(&d.join("org-entities.json"), &p.entities)?;
        write_replace(&d.join("org.cedar"), &p.text)?;
        write_replace(&d.join("installed"), &v)?;
        l.audit(
            &wicket_core::TenantId::single(),
            None,
            "policy.applied",
            &serde_json::json!({ "version": v, "previous": prev, "by": by, "decision": decision, "effect_sha256": pre.effect_sha256 }),
        )?;
        println!("org policy {v} applied (was {})", prev.as_deref().unwrap_or("none"));
    }
    // Runs minted under another version: revoked (their supervisors stop the boxes and publish the
    // revocation of their tokens to the nodes), unless kept until they end.
    if pre.runs.is_empty() {
        return Ok(());
    }
    if pre.keep_runs {
        println!("{} running run(s) keep the policy they were minted under until they end (--keep-runs)", pre.runs.len());
        return Ok(());
    }
    let reason = format!("org policy {v} applied; this run was minted under an older version");
    for r in pre.revokes() {
        let fresh = l.revoke(&r.run, by, &reason)?;
        l.audit(
            &wicket_core::TenantId::single(),
            Some(&wicket_core::RunId(r.run.clone())),
            "identity.revoked",
            &serde_json::json!({ "run": r.run, "by": by, "reason": reason, "policy": r.policy, "decision": decision }),
        )?;
        println!("{} {} (policy {})", if fresh { "revoked" } else { "already revoked" }, r.run, r.policy.as_deref().unwrap_or("none"));
    }
    println!("their runners stop the boxes within seconds, and publish the revocation of their tokens to the nodes");
    Ok(())
}

/// `wicket policy zone MANIFEST`: the zone's policy, as Cedar.
pub fn zone(manifest: &Path) -> Result<()> {
    let m = wicket_agent::load(&std::fs::read_to_string(manifest).with_context(|| manifest.display().to_string())?)?;
    let base = wicket_authz::Ceiling::from_zone(&m.zone, "run", 0, vec![])?;
    let (text, _) = wicket_policy::zone_layer(&m.zone, &base).context("the zone's policy doesn't compile")?;
    print!("{text}");
    println!("// (a box may also start children from its own image: its token's spawn permit names it)");
    Ok(())
}

/// Refuses a policy file that isn't Cedar text (a likely mistake: a manifest passed to apply).
pub fn sanity(file: &Path) -> Result<()> {
    if file.extension().is_some_and(|e| e == "yaml" || e == "yml") {
        bail!("{}: an org policy is Cedar text (org.cedar), not YAML", file.display());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grant::Granter;
    use crate::operators::{Operator, Policy};
    use wicket_core::{RunId, TenantId};

    const ORG: &str = include_str!("../../../examples/policy/org.cedar");
    const ENTITIES: &str = include_str!("../../../examples/policy/org-entities.json");

    fn human(policy: &str) -> Granter {
        Granter::Human(Operator::new("default", "passkey", "laptop", "passkey:laptop".into(), &Policy::parse(policy).unwrap()))
    }

    fn running(l: &wicket_store::Ledger, run: &str, policy: Option<&str>) {
        l.run_started(&TenantId::single(), &RunId(run.into()), "z", "a").unwrap();
        l.put_identity(&wicket_store::IdentityRow {
            run: run.into(),
            tenant: TenantId::single().0,
            spiffe_id: format!("spiffe://w.test/t/{run}"),
            zone: "z".into(),
            agent: "a".into(),
            parent_run: None,
            accept_from: vec![],
            jws: "x.y.z".into(),
            issued_at: wicket_store::now(),
        })
        .unwrap();
        if let Some(p) = policy {
            l.set_run_policy(run, Some(p)).unwrap();
        }
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-policy-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// #712: what an apply would do, and a console decision bound to it, checked by the apply.
    #[test]
    fn a_policy_is_previewed_decided_on_its_effect_and_the_decision_checked_once() {
        let data = tmp("decide");
        let l = wicket_store::Ledger::open_in_memory().unwrap();
        let org = parse(ORG, ENTITIES).unwrap();
        running(&l, "run_old", Some("0123"));
        running(&l, "run_none", None);
        let pre = preview_in(&org, &data, &l, false).unwrap();
        assert_eq!((pre.previous.as_deref(), pre.already), (None, false));
        assert!(pre.refused.is_empty(), "{:?}", pre.refused);
        assert_eq!(pre.runs.iter().map(|r| r.run.as_str()).collect::<Vec<_>>(), ["run_old", "run_none"]);
        assert_eq!(pre.revokes().len(), 2);
        let kept = preview_in(&org, &data, &l, true).unwrap();
        assert!(kept.revokes().is_empty());
        assert_ne!(kept.effect_sha256, pre.effect_sha256, "--keep-runs is part of the effect");
        let text = preview_text(&pre);
        assert!(text.contains("it revokes 2 running run(s)") && text.contains("run_old  zone z  policy 0123"), "{text}");

        for (by, why) in
            [(human("default: nothing\n"), "may decide nothing"), (human("default: { kinds: [fence] }\n"), "may not decide policy")]
        {
            let e = decide(&l, &by, &org, &data, false, &pre.effect_sha256, serde_json::json!({})).unwrap_err();
            assert!(format!("{e:#}").contains(why), "{e:#}");
        }
        let anyone = human("default: anything\n");
        // A run started after it was shown: what it does changed.
        running(&l, "run_new", None);
        let e = decide(&l, &anyone, &org, &data, false, &pre.effect_sha256, serde_json::json!({})).unwrap_err();
        assert!(format!("{e:#}").contains("changed after you were shown it"), "{e:#}");
        assert_eq!(l.audit_tail(10).unwrap().iter().filter(|r| r.2 == "decision.refused").count(), 3);

        let pre = preview_in(&org, &data, &l, false).unwrap();
        let (p2, seq) = decide(&l, &anyone, &org, &data, false, &pre.effect_sha256, serde_json::json!({ "via": "console" })).unwrap();
        assert_eq!(p2, pre);
        let rec = l.audit_record_at(seq).unwrap().unwrap();
        assert_eq!(rec.kind, "policy.apply_decided");
        let b: serde_json::Value = serde_json::from_str(&rec.body).unwrap();
        assert_eq!(
            (b["by"].as_str(), b["via"].as_str(), b["revokes"].as_array().map(Vec::len)),
            (Some("passkey:laptop"), Some("console"), Some(3))
        );

        // The apply it starts: this decision, for this version and keep_runs, on this effect, once.
        assert_eq!(decided(&l, seq, &pre).unwrap(), "passkey:laptop");
        assert!(format!("{:#}", decided(&l, seq, &kept).unwrap_err()).contains("another policy or --keep-runs"));
        assert!(decided(&l, seq + 99, &pre).is_err(), "no such decision");
        l.run_ended(&RunId("run_new".into()), "ok", "done").unwrap();
        let moved = preview_in(&org, &data, &l, false).unwrap();
        assert!(format!("{:#}", decided(&l, seq, &moved).unwrap_err()).contains("changed since it was decided"));
        l.audit(&TenantId::single(), None, "policy.applied", &serde_json::json!({ "version": pre.version, "decision": seq })).unwrap();
        assert!(format!("{:#}", decided(&l, seq, &pre).unwrap_err()).contains("used already"));
        std::fs::remove_dir_all(&data).unwrap();
    }

    /// A policy that doesn't mint is refused at the decision, before anything is recorded as decided.
    #[test]
    fn a_policy_that_doesnt_mint_isnt_decided() {
        let data = tmp("nomint");
        let l = wicket_store::Ledger::open_in_memory().unwrap();
        // Over the node's structural caps: more alternatives than a token may carry.
        let many: String = (0..400)
            .map(|i| format!("permit(principal, action == Action::\"GET\", resource) when {{ resource.host == \"h{i}.example.com\" }};\n"))
            .collect();
        let org = parse(&many, "").unwrap();
        let pre = preview_in(&org, &data, &l, false).unwrap();
        assert!(!pre.refused.is_empty(), "400 alternatives are over a token's caps");
        let e = decide(&l, &human("default: anything\n"), &org, &data, false, &pre.effect_sha256, serde_json::json!({})).unwrap_err();
        assert!(format!("{e:#}").contains("doesn't mint"), "{e:#}");
        assert!(!l.audit_tail(10).unwrap().iter().any(|r| r.2 == "policy.apply_decided"));
        std::fs::remove_dir_all(&data).unwrap();
    }
}
