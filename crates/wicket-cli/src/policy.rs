//! `wicket policy` (#51): the installation's org policy in Cedar, and each zone's.
//!
//! The org policy is `<data dir>/policy/org.cedar`, with the groups zones are in in
//! `org-entities.json` (Cedar entities JSON). With none, tokens carry no org layer. Every token is
//! compiled at mint from the policy current then, and records its version (block 0's `policy`
//! fact, and the run's ledger row). `wicket policy apply` installs a new version and revokes the
//! runs minted under older ones, so no box goes on under a policy that's no longer the
//! installation's.

use crate::{data_dir, ledger_path};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use wicket_policy::{MintCtx, OrgPolicy};

fn dir() -> PathBuf {
    data_dir().join("policy")
}

/// The installation's org policy, if it has one.
pub fn org() -> Result<Option<OrgPolicy>> {
    let p = dir().join("org.cedar");
    let text = match std::fs::read_to_string(&p) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| p.display().to_string()),
    };
    let ents = std::fs::read_to_string(dir().join("org-entities.json")).unwrap_or_else(|_| "[]".into());
    Ok(Some(OrgPolicy::parse(&text, &ents).with_context(|| p.display().to_string())?))
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
    println!("{}: version {}, validates against wicket's schema and compiles", file.display(), p.version());
    println!("  {}", summary(&p)?);
    Ok(())
}

/// `wicket policy show`.
pub fn show() -> Result<()> {
    let cur = org()?;
    match &cur {
        Some(p) => {
            println!("org policy {} ({})", p.version(), dir().join("org.cedar").display());
            println!("  {}", summary(p)?);
        }
        None => println!("no org policy ({} doesn't exist): tokens carry zone policy only", dir().join("org.cedar").display()),
    }
    let l = wicket_store::Ledger::open(&ledger_path())?;
    let want = cur.as_ref().map(|p| p.version());
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
pub fn apply(file: &Path, entities: Option<&Path>, keep_runs: bool) -> Result<()> {
    let p = load(file, entities)?;
    let v = p.version();
    let prev = org()?.map(|o| o.version());
    if prev.as_deref() == Some(v.as_str()) {
        println!("org policy {v} is already the installation's");
    } else {
        let d = dir();
        std::fs::create_dir_all(d.join("versions"))?;
        // Every version is kept, by its hash, for review and rollback.
        std::fs::write(d.join("versions").join(format!("{v}.cedar")), &p.text)?;
        std::fs::write(d.join("versions").join(format!("{v}.entities.json")), &p.entities)?;
        write_replace(&d.join("org-entities.json"), &p.entities)?;
        write_replace(&d.join("org.cedar"), &p.text)?;
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
    if base.spawn.images.is_empty() {
        println!("// (a box may also start children from its own image: its token's spawn permit names it)");
    }
    Ok(())
}

/// Refuses a policy file that isn't Cedar text (a likely mistake: a manifest passed to apply).
pub fn sanity(file: &Path) -> Result<()> {
    if file.extension().is_some_and(|e| e == "yaml" || e == "yml") {
        bail!("{}: an org policy is Cedar text (org.cedar), not YAML", file.display());
    }
    Ok(())
}
