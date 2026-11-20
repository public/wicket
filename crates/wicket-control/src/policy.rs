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
    /// The sha256 of its Cedar text and of its entities JSON: what the version (64 bits) names.
    pub cedar_sha256: String,
    pub entities_sha256: String,
    /// What it changes against the applied policy, per context: each running zone with its groups
    /// (under the old entities and the new), each group alone, and a zone in no group. Only the
    /// contexts where the compiled layers differ.
    pub changes: Vec<LayerChange>,
    /// Whether any change may widen what a box may do.
    pub widens: bool,
    /// What couldn't be compared, and why (a run's zone that couldn't be read, groups over the cap,
    /// an applied policy that doesn't parse).
    pub unchecked: Vec<String>,
    /// What the human decides on: the version and its sources' digests, the one it replaces, the
    /// changes, and which runs it revokes.
    pub effect_sha256: String,
}

/// How the compiled org layer for one context differs between the applied policy and the new one.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct LayerChange {
    /// Which box it is for: `zone z (groups …)`, `a zone in group g`, `a zone in no group`.
    pub context: String,
    /// What the new policy may allow that the applied one didn't: a permit added, a forbid removed,
    /// a constraint lifted. An added alternative is shown as widening even where another covered it.
    pub widens: Vec<String>,
    /// What it no longer allows.
    pub narrows: Vec<String>,
}

/// The most groups compared alone, and minted for alone: more are listed as unchecked.
pub const MAX_GROUPS: usize = 32;

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

/// The applied org policy in the installation's `policy/` directory `pdir`, if one was applied.
fn applied_in(pdir: &Path) -> Result<Option<OrgPolicy>> {
    let Some(v) = installed_in(pdir) else { return Ok(None) };
    let text = std::fs::read_to_string(pdir.join("org.cedar")).with_context(|| format!("the applied policy {v}'s org.cedar"))?;
    Ok(Some(OrgPolicy::parse(&text, &entities_in(pdir)).with_context(|| format!("the applied policy {v}"))?))
}

/// The groups a policy's entities name.
fn groups_in(org: &OrgPolicy) -> BTreeSet<String> {
    org.entities().iter().filter(|e| e.uid().type_name().to_string() == "Group").map(|e| e.uid().id().unescaped().to_string()).collect()
}

/// One op kind's alternatives (None: unconstrained), old against new.
fn alts<T: serde::Serialize>(what: &str, old: Option<&Option<Vec<T>>>, new: &Option<Vec<T>>, out: &mut LayerChange) {
    let show = |xs: &[T]| -> BTreeSet<String> { xs.iter().map(|x| serde_json::to_string(x).unwrap_or_default()).collect() };
    // No policy applied: nothing was constrained.
    let old = old.unwrap_or(&None);
    match (old, new) {
        (None, None) => {}
        (None, Some(b)) => out.narrows.push(format!("{what}: constrained to {} alternative(s), where it was unconstrained", b.len())),
        (Some(a), None) => out.widens.push(format!("{what}: unconstrained, where it was constrained to {} alternative(s)", a.len())),
        (Some(a), Some(b)) => {
            let (a, b) = (show(a), show(b));
            out.widens.extend(b.difference(&a).map(|x| format!("{what}: allows {x}")));
            out.narrows.extend(a.difference(&b).map(|x| format!("{what}: no longer allows {x}")));
        }
    }
}

/// How `new`'s layer differs from `old`'s (None: no policy applied) for one context.
fn layer_diff(context: String, old: Option<&wicket_authz::OrgLayer>, new: &wicket_authz::OrgLayer) -> LayerChange {
    let mut c = LayerChange { context, widens: vec![], narrows: vec![] };
    alts("http", old.map(|o| &o.http), &new.http, &mut c);
    alts("spawn", old.map(|o| &o.spawn), &new.spawn, &mut c);
    alts("messages from", old.map(|o| &o.msg_from), &new.msg_from, &mut c);
    alts("injections", old.map(|o| &o.inject), &new.inject, &mut c);
    let show =
        |xs: &[wicket_authz::HttpMatch]| -> BTreeSet<String> { xs.iter().map(|x| serde_json::to_string(x).unwrap_or_default()).collect() };
    let (a, b) = (old.map(|o| show(&o.forbid)).unwrap_or_default(), show(&new.forbid));
    c.narrows.extend(b.difference(&a).map(|x| format!("forbid: {x}")));
    c.widens.extend(a.difference(&b).map(|x| format!("forbid removed: {x}")));
    c
}

/// [`Preview`] of `org` against the installation in `data` (its `policy/` and its runs' records) and
/// its ledger `l`.
pub fn preview_in(org: &OrgPolicy, data: &Path, l: &wicket_store::Ledger, keep_runs: bool) -> Result<Preview> {
    use sha2::Digest;
    let sha = |s: &str| hex::encode(sha2::Sha256::digest(s.as_bytes()));
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
    // What it changes, against what is applied now, for each context a box can be minted in.
    let (zones, mut unchecked) = zones_to_check(data, Some(l));
    let old = match applied_in(&pdir) {
        Ok(o) => o,
        Err(e) => {
            unchecked.push(format!("the applied policy can't be read, so nothing is compared with it: {e:#}"));
            None
        }
    };
    let old_groups = old.as_ref().map(groups_in).unwrap_or_default();
    let groups: Vec<String> = old_groups.union(&groups_in(org)).cloned().collect();
    if groups.len() > MAX_GROUPS {
        unchecked.push(format!("groups beyond the first {MAX_GROUPS}, not compared alone: {}", groups[MAX_GROUPS..].join(", ")));
    }
    let mut contexts: Vec<(String, String, BTreeSet<String>, BTreeSet<String>)> = vec![];
    for (what, z) in &zones {
        let (og, ng) = (old.as_ref().map(|o| o.groups_of(&z.name)).unwrap_or_default(), org.groups_of(&z.name));
        contexts.push((format!("{what} (groups {og:?} → {ng:?})"), z.name.clone(), og, ng));
    }
    contexts.push(("a zone in no group".into(), "policy-check".into(), BTreeSet::new(), BTreeSet::new()));
    for g in groups.iter().take(MAX_GROUPS) {
        let one = BTreeSet::from([g.clone()]);
        contexts.push((format!("a zone in group {g}"), "policy-check".into(), one.clone(), one));
    }
    let mut changes = vec![];
    for (context, zone, og, ng) in contexts {
        let ctx = |groups| MintCtx { zone: zone.clone(), tenant: "t".into(), principal: "human:check".into(), depth: 0, groups };
        let new_layer = match org.layer(&ctx(ng)) {
            Ok(x) => x,
            Err(e) => {
                unchecked.push(format!("{context}: the new policy doesn't compile for it: {e}"));
                continue;
            }
        };
        let old_layer = match old.as_ref().map(|o| o.layer(&ctx(og))).transpose() {
            Ok(x) => x,
            Err(e) => {
                unchecked.push(format!("{context}: the applied policy doesn't compile for it: {e}"));
                continue;
            }
        };
        let c = layer_diff(context, old_layer.as_ref(), &new_layer);
        if !c.widens.is_empty() || !c.narrows.is_empty() {
            changes.push(c);
        }
    }
    let widens = changes.iter().any(|c| !c.widens.is_empty());
    let (cedar_sha256, entities_sha256) = (sha(&org.text), sha(&org.entities));
    let diff_sha256 = sha(&serde_json::json!({ "changes": changes, "unchecked": unchecked }).to_string());
    let revoked: Vec<&str> = if keep_runs { vec![] } else { runs.iter().map(|r| r.run.as_str()).collect() };
    let effect = serde_json::json!({ "v": 2, "kind": "policy_apply", "version": version, "cedar_sha256": cedar_sha256,
                                     "entities_sha256": entities_sha256, "previous": previous, "keep_runs": keep_runs,
                                     "diff_sha256": diff_sha256, "revokes": revoked });
    Ok(Preview {
        summary: summary(org)?,
        refused: trial_in(org, data, Some(l)),
        effect_sha256: sha(&effect.to_string()),
        version,
        previous,
        already,
        runs,
        keep_runs,
        cedar_sha256,
        entities_sha256,
        changes,
        widens,
        unchecked,
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
    if p.changes.is_empty() {
        o.push_str("  it changes nothing a box may do, against the applied policy\n");
    } else {
        o.push_str(&format!(
            "  against the applied policy it {}:\n",
            if p.widens { "WIDENS what boxes may do" } else { "only narrows what boxes may do" }
        ));
        for c in &p.changes {
            o.push_str(&format!("    {}\n", c.context));
            for w in &c.widens {
                o.push_str(&format!("      + {w}\n"));
            }
            for n in &c.narrows {
                o.push_str(&format!("      - {n}\n"));
            }
        }
    }
    if !p.unchecked.is_empty() {
        o.push_str(&format!("  not compared:\n    - {}\n", p.unchecked.join("\n    - ")));
    }
    o.push_str(&format!("  cedar sha256 {}, entities sha256 {}\n", p.cedar_sha256, p.entities_sha256));
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
            "what applying it does changed after you were shown it (what it changes, the runs it revokes, or the applied version): look again"
        )));
    }
    let mut rec = serde_json::json!({
        "action": "policy_apply", "version": pre.version, "cedar_sha256": pre.cedar_sha256, "entities_sha256": pre.entities_sha256,
        "previous": pre.previous, "keep_runs": keep_runs, "widens": pre.widens, "changes": pre.changes, "unchecked": pre.unchecked,
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
    if b["version"].as_str() != Some(p.version.as_str())
        || b["cedar_sha256"].as_str() != Some(p.cedar_sha256.as_str())
        || b["entities_sha256"].as_str() != Some(p.entities_sha256.as_str())
        || b["keep_runs"].as_bool() != Some(p.keep_runs)
    {
        bail!("decision {seq} is for another policy (its Cedar or entities) or --keep-runs");
    }
    if wicket_store::now() - r.ts > DECISION_TTL_SECS {
        bail!("decision {seq} is older than {} minutes: decide again", DECISION_TTL_SECS / 60);
    }
    for kind in ["policy.applied", "policy.apply_failed", "policy.apply_incomplete", "policy.apply_finished"] {
        if l.audit_of_kind(kind)?
            .iter()
            .any(|x| serde_json::from_str::<serde_json::Value>(&x.body).is_ok_and(|v| v["decision"].as_i64() == Some(seq)))
        {
            bail!("decision {seq} was used already");
        }
    }
    if b["effect_sha256"].as_str() != Some(p.effect_sha256.as_str()) {
        bail!("what applying it does changed since it was decided (what it changes, the runs it revokes, or the applied version): decide again");
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

/// The zones the check mints for: every running run's (from its record under `data`, once per
/// zone), and a bare one; and the runs whose zone couldn't be read.
fn zones_to_check(data: &Path, l: Option<&wicket_store::Ledger>) -> (Vec<(String, wicket_core::ZoneSpec)>, Vec<String>) {
    let bare: wicket_core::ZoneSpec = wicket_core::yaml::from_str("name: policy-check\n").expect("a bare zone");
    let mut out = vec![("a zone with no rules".to_string(), bare)];
    let mut unread = vec![];
    let opened = if l.is_none() { wicket_store::Ledger::open(&ledger_path()).ok() } else { None };
    if let Some(l) = l.or(opened.as_ref()) {
        for (run, _, _) in l.running_policies().unwrap_or_default() {
            let rec = data.join("runs").join(&run).join("ctl/run.json");
            let m = std::fs::read(&rec)
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|v| v["manifest"].as_str().and_then(|y| wicket_agent::load(y).ok()));
            match m {
                Some(m) if out.iter().any(|(_, z)| z.name == m.zone.name) => {}
                Some(m) => out.push((format!("run {run}'s zone {}", m.zone.name), m.zone)),
                None => unread.push(format!("run {run}'s zone: its record ({}) can't be read", rec.display())),
            }
        }
    }
    (out, unread)
}

/// Compiles and mints `org` for each zone to check, as a member of no group, of every group, and of
/// each group alone. Returns what failed.
fn trial(org: &OrgPolicy) -> Vec<String> {
    trial_in(org, &data_dir(), None)
}

/// [`trial`] against the installation in `data` and its ledger (None: the installation's).
fn trial_in(org: &OrgPolicy, data: &Path, l: Option<&wicket_store::Ledger>) -> Vec<String> {
    let all = groups_in(org);
    let mut sets = vec![BTreeSet::new(), all.clone()];
    sets.extend(all.iter().take(MAX_GROUPS).map(|g| BTreeSet::from([g.clone()])));
    let mut bad = vec![];
    for (what, z) in zones_to_check(data, l).0 {
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
/// console's, #712), only what that signed decision previewed is applied, once; an apply that fails
/// before it installs anything is audited `policy.apply_failed`, and the policy files the console
/// staged for it are removed afterwards.
pub async fn apply(file: &Path, entities: Option<&Path>, keep_runs: bool, dry_run: bool, decision: Option<i64>) -> Result<()> {
    if dry_run {
        let p = load(file, entities)?;
        let l = wicket_store::Ledger::open(&ledger_path())?;
        print!("{}", preview_text(&preview_in(&p, &data_dir(), &l, keep_runs)?));
        return Ok(());
    }
    let mut installed = false;
    let mut version = None;
    let r = async {
        let p = load(file, entities)?;
        version = Some(p.version());
        let l = wicket_store::Ledger::open(&ledger_path())?;
        let pre = preview_in(&p, &data_dir(), &l, keep_runs)?;
        install(&p, &pre, decision, &mut installed).await
    }
    .await;
    if let (Err(e), Some(seq), false) = (&r, decision, installed) {
        if let Ok(l) = wicket_store::Ledger::open(&ledger_path()) {
            let _ = l.audit(
                &wicket_core::TenantId::single(),
                None,
                "policy.apply_failed",
                &serde_json::json!({ "version": version, "decision": seq, "error": format!("{e:#}") }),
            );
        }
    }
    if decision.is_some() {
        let staged = dir().join("staged");
        for f in [Some(file), entities].into_iter().flatten() {
            if f.parent() == Some(staged.as_path()) {
                let _ = std::fs::remove_file(f);
            }
        }
    }
    r
}

/// Held while an apply checks, installs and revokes: one apply at a time.
struct ApplyLock(#[allow(dead_code)] std::fs::File);

impl ApplyLock {
    fn take() -> Result<ApplyLock> {
        use std::os::fd::AsRawFd;
        let d = dir();
        std::fs::create_dir_all(&d)?;
        let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(d.join("apply.lock"))?;
        // SAFETY: flock on a file descriptor this function owns.
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(std::io::Error::last_os_error()).context("locking policy/apply.lock");
        }
        Ok(ApplyLock(f))
    }
}

/// Installs `p`, previewed as `pre`, and revokes the runs minted under another version unless
/// `pre.keep_runs`. With `decision`, as the console's decision says and only if it holds. Sets
/// `installed` once the policy is the installation's; a failure after that is audited
/// `policy.apply_incomplete`, and the end `policy.apply_finished`.
async fn install(p: &OrgPolicy, pre: &Preview, decision: Option<i64>, installed: &mut bool) -> Result<()> {
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
    // From here to the end, one apply at a time.
    let _lock = ApplyLock::take()?;
    let l = wicket_store::Ledger::open(&ledger_path())?;
    let now = preview_in(p, &data_dir(), &l, pre.keep_runs)?;
    let by = match decision {
        // A decided apply is of what was shown, checked again now the nodes have answered.
        Some(seq) => decided(&l, seq, &now)?,
        None => crate::operator(),
    };
    let prev = installed_in(&dir());
    if now.already {
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
        *installed = true;
        let r = l.audit(
            &wicket_core::TenantId::single(),
            None,
            "policy.applied",
            &serde_json::json!({ "version": v, "previous": prev, "by": by, "decision": decision, "effect_sha256": now.effect_sha256,
                                 "cedar_sha256": now.cedar_sha256, "entities_sha256": now.entities_sha256, "widens": now.widens }),
        );
        if let Err(e) = r {
            return Err(incomplete(&l, &v, decision, anyhow::Error::from(e).context("recording policy.applied")));
        }
        println!("org policy {v} applied (was {})", prev.as_deref().unwrap_or("none"));
    }
    *installed = true;
    match revoke_older(&l, &v, &now, &by, decision) {
        Ok(()) => Ok(()),
        Err(e) => Err(incomplete(&l, &v, decision, e)),
    }
}

/// Audits an apply that installed its policy and then failed (`policy.apply_incomplete`).
fn incomplete(l: &wicket_store::Ledger, v: &str, decision: Option<i64>, e: anyhow::Error) -> anyhow::Error {
    let _ = l.audit(
        &wicket_core::TenantId::single(),
        None,
        "policy.apply_incomplete",
        &serde_json::json!({ "version": v, "decision": decision, "installed": true, "error": format!("{e:#}") }),
    );
    e.context(format!("org policy {v} is installed, but the apply didn't finish (policy.apply_incomplete)"))
}

/// Revokes the runs minted under another version than `v`, as they are once `v` is installed (a run
/// started while the nodes were asked is one of them), unless `--keep-runs`; then
/// `policy.apply_finished`, with any revoked beyond what was previewed.
fn revoke_older(l: &wicket_store::Ledger, v: &str, pre: &Preview, by: &str, decision: Option<i64>) -> Result<()> {
    let mut runs = vec![];
    for (run, zone, pv) in l.running_policies()? {
        if pv.as_deref() != Some(v) && l.identity(&run)?.is_some() {
            runs.push(RunChange { run, zone, policy: pv });
        }
    }
    let mut revoked = vec![];
    if pre.keep_runs {
        if !runs.is_empty() {
            println!("{} running run(s) keep the policy they were minted under until they end (--keep-runs)", runs.len());
        }
    } else {
        let reason = format!("org policy {v} applied; this run was minted under an older version");
        for r in &runs {
            let fresh = l.revoke(&r.run, by, &reason)?;
            l.audit(
                &wicket_core::TenantId::single(),
                Some(&wicket_core::RunId(r.run.clone())),
                "identity.revoked",
                &serde_json::json!({ "run": r.run, "by": by, "reason": reason, "policy": r.policy, "decision": decision }),
            )?;
            println!("{} {} (policy {})", if fresh { "revoked" } else { "already revoked" }, r.run, r.policy.as_deref().unwrap_or("none"));
            revoked.push(r.run.clone());
        }
        if !revoked.is_empty() {
            println!("their runners stop the boxes within seconds, and publish the revocation of their tokens to the nodes");
        }
    }
    let beyond: Vec<&String> = revoked.iter().filter(|r| !pre.runs.iter().any(|x| &x.run == *r)).collect();
    l.audit(
        &wicket_core::TenantId::single(),
        None,
        "policy.apply_finished",
        &serde_json::json!({ "version": v, "decision": decision, "already": pre.already, "revoked": revoked,
                             "revoked_beyond_preview": beyond, "kept": if pre.keep_runs { runs.len() } else { 0 }, "by": by }),
    )?;
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
        assert!(format!("{:#}", decided(&l, seq, &kept).unwrap_err()).contains("or --keep-runs"));
        let mut other = pre.clone();
        other.cedar_sha256 = "0".repeat(64);
        assert!(format!("{:#}", decided(&l, seq, &other).unwrap_err()).contains("its Cedar or entities"));
        assert!(decided(&l, seq + 99, &pre).is_err(), "no such decision");
        l.run_ended(&RunId("run_new".into()), "ok", "done").unwrap();
        let moved = preview_in(&org, &data, &l, false).unwrap();
        assert!(format!("{:#}", decided(&l, seq, &moved).unwrap_err()).contains("changed since it was decided"));
        l.audit(&TenantId::single(), None, "policy.applied", &serde_json::json!({ "version": pre.version, "decision": seq })).unwrap();
        assert!(format!("{:#}", decided(&l, seq, &pre).unwrap_err()).contains("used already"));
        std::fs::remove_dir_all(&data).unwrap();
    }

    /// #782 review: the preview says what changes against the applied policy, per context. A policy
    /// that drops one group's forbid widens for that group alone, and the change is in the effect.
    #[test]
    fn the_preview_diffs_the_compiled_layers_against_the_applied_policy() {
        let data = tmp("diff");
        let l = wicket_store::Ledger::open_in_memory().unwrap();
        let pdir = data.join("policy");
        std::fs::create_dir_all(&pdir).unwrap();
        std::fs::write(pdir.join("org.cedar"), ORG).unwrap();
        std::fs::write(pdir.join("org-entities.json"), ENTITIES).unwrap();
        std::fs::write(pdir.join("installed"), wicket_policy::version(ORG, ENTITIES)).unwrap();

        let same = preview_in(&parse(ORG, ENTITIES).unwrap(), &data, &l, false).unwrap();
        assert!(same.already && same.changes.is_empty() && !same.widens, "{:?}", same.changes);
        assert!(preview_text(&same).contains("changes nothing a box may do"));

        // The development zones' write forbid, removed.
        let start = ORG.find("// Development zones").unwrap();
        let end = ORG[start..].find("\n\n").unwrap() + start;
        let wider = format!("{}{}", &ORG[..start], &ORG[end..]);
        let p = preview_in(&parse(&wider, ENTITIES).unwrap(), &data, &l, false).unwrap();
        assert!(p.widens, "{p:?}");
        let ctx: Vec<&str> = p.changes.iter().map(|c| c.context.as_str()).collect();
        assert_eq!(ctx, ["a zone in group dev"], "only that group's boxes: {:?}", p.changes);
        assert!(p.changes[0].widens.iter().all(|w| w.starts_with("forbid removed")), "{:?}", p.changes[0]);
        assert!(preview_text(&p).contains("WIDENS"));
        assert_ne!(p.effect_sha256, preview_in(&parse(ORG, "[]").unwrap(), &data, &l, false).unwrap().effect_sha256);

        // Entities that move a running zone into `dev`: that zone's boxes lose the forbid.
        running(&l, "run_api", None);
        let rec = data.join("runs/run_api/ctl");
        std::fs::create_dir_all(&rec).unwrap();
        let manifest = "task: t\nprogram: { name: p, command: [x] }\nzone: { name: api }\n";
        std::fs::write(rec.join("run.json"), serde_json::to_vec(&serde_json::json!({ "manifest": manifest })).unwrap()).unwrap();
        // Another running run whose record can't be read is said, not skipped.
        running(&l, "run_lost", None);
        let moved = ENTITIES.replace("\"id\": \"dev-api\"", "\"id\": \"api\"");
        let p = preview_in(&parse(ORG, &moved).unwrap(), &data, &l, false).unwrap();
        let api = p.changes.iter().find(|c| c.context.contains("zone api")).expect("the moved zone's change");
        assert!(api.narrows.iter().any(|n| n.starts_with("forbid:")), "moving into dev adds its forbid: {api:?}");
        assert!(p.unchecked.iter().any(|u| u.contains("run run_lost's zone")), "{:?}", p.unchecked);

        // No policy applied: a first policy only narrows.
        std::fs::remove_file(pdir.join("installed")).unwrap();
        let first = preview_in(&parse(ORG, ENTITIES).unwrap(), &data, &l, false).unwrap();
        assert!(!first.widens && !first.changes.is_empty(), "{:?}", first.changes);
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
