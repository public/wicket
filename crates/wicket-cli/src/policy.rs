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

/// The zones the check mints for: every running run's (from its record), and a bare one.
fn zones_to_check() -> Vec<(String, wicket_core::ZoneSpec)> {
    let bare: wicket_core::ZoneSpec = serde_yaml::from_str("name: policy-check\n").expect("a bare zone");
    let mut out = vec![("a zone with no rules".to_string(), bare)];
    if let Ok(l) = wicket_store::Ledger::open(&ledger_path()) {
        for (run, _, _) in l.running_policies().unwrap_or_default() {
            let rec = data_dir().join("runs").join(&run).join("ctl/run.json");
            let m = std::fs::read(&rec)
                .ok()
                .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
                .and_then(|v| v["manifest"].as_str().and_then(|y| wicket_core::Manifest::from_yaml(y).ok()));
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
    let all: BTreeSet<String> = org
        .entities()
        .iter()
        .filter(|e| e.uid().type_name().to_string() == "Group")
        .map(|e| e.uid().id().unescaped().to_string())
        .collect();
    let mut sets = vec![BTreeSet::new(), all.clone()];
    sets.extend(all.iter().map(|g| BTreeSet::from([g.clone()])));
    let mut bad = vec![];
    for (what, z) in zones_to_check() {
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
    let tmp = p.with_extension("new");
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, p)?;
    Ok(())
}

/// `wicket policy apply FILE [--entities F] [--keep-runs]`.
pub async fn apply(file: &Path, entities: Option<&Path>, keep_runs: bool) -> Result<()> {
    let p = load(file, entities)?;
    let v = p.version();
    // Nothing changes unless it mints for every running run's zone, and every node reads it.
    let bad = trial(&p);
    if !bad.is_empty() {
        bail!("org policy {v} doesn't mint, so nothing changed:\n  - {}", bad.join("\n  - "));
    }
    let lacking = crate::roots::nodes_below(crate::chan::ORG_POLICY).await?;
    if !lacking.is_empty() {
        bail!(
            "not every node can read tokens with an org layer; nothing changed:\n{}\n(update them, or revoke the ones you no longer use)",
            lacking.iter().map(|(n, why)| format!("  - node {n}: {why}")).collect::<Vec<_>>().join("\n")
        );
    }
    let prev = installed();
    if prev.as_deref() == Some(v.as_str()) && dir().join("org.cedar").exists() {
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
        let l = wicket_store::Ledger::open(&ledger_path())?;
        l.audit(
            &wicket_core::TenantId::single(),
            None,
            "policy.applied",
            &serde_json::json!({ "version": v, "previous": prev, "by": crate::operator() }),
        )?;
        println!("org policy {v} applied (was {})", prev.as_deref().unwrap_or("none"));
    }
    // Runs minted under another version: revoked (their supervisors stop the boxes and publish the
    // revocation of their tokens to the nodes), unless kept until they end.
    let l = wicket_store::Ledger::open(&ledger_path())?;
    let old: Vec<(String, String, Option<String>)> =
        l.running_policies()?.into_iter().filter(|(_, _, pv)| pv.as_deref() != Some(v.as_str())).collect();
    if old.is_empty() {
        return Ok(());
    }
    if keep_runs {
        println!("{} running run(s) keep the policy they were minted under until they end (--keep-runs)", old.len());
        return Ok(());
    }
    let reason = format!("org policy {v} applied; this run was minted under an older version");
    for (run, _, pv) in &old {
        if l.identity(run)?.is_none() {
            continue;
        }
        let fresh = l.revoke(run, &crate::operator(), &reason)?;
        l.audit(
            &wicket_core::TenantId::single(),
            Some(&wicket_core::RunId(run.clone())),
            "identity.revoked",
            &serde_json::json!({ "run": run, "by": crate::operator(), "reason": reason, "policy": pv }),
        )?;
        println!("{} {run} (policy {})", if fresh { "revoked" } else { "already revoked" }, pv.as_deref().unwrap_or("none"));
    }
    println!("their runners stop the boxes within seconds, and publish the revocation of their tokens to the nodes");
    Ok(())
}

/// `wicket policy zone MANIFEST`: the zone's policy, as Cedar.
pub fn zone(manifest: &Path) -> Result<()> {
    let m = wicket_core::Manifest::from_yaml(&std::fs::read_to_string(manifest).with_context(|| manifest.display().to_string())?)?;
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
