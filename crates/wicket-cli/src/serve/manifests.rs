//! The console's manifest viewer and editor (#172).
//!
//! - **Viewer** (`GET /api/manifests/<root>/<name>`): the raw YAML and whether it validates (the
//!   same `Manifest::from_yaml` `wicket run` uses), every field with its effective value and whether
//!   it was written or defaulted, the hosts the egress proxy splices or inspects, the image, each
//!   injection's secret by name and whether the vault has it (never a value), and the effective
//!   policy with the installation's org policy, if one is applied. The installation's manifests also
//!   list their saved versions.
//! - **Check** (`POST /api/manifests/check`): validates edited YAML as the operator types, and
//!   diffs its authority against the saved version: what it adds and removes, and whether it widens
//!   anything (`wicket_core::subset::check`, the same test a spawn's zone passes against its parent's,
//!   with the saved version as the parent). Read-only, unsigned.
//! - **Save** and **restore** are signed console actions (`save_manifest`, `restore_manifest`): the
//!   passkey signs the new bytes' sha256, the sha256 they replace, and the authority diff. Applying one
//!   checks the file is still the version it replaces, keeps that version in
//!   `manifests/.history/<name>/`, writes the new one, and audits `manifest.saved` with the signed
//!   record. Only the installation's `manifests` directory is written. Runs keep the manifest they
//!   started with: each run records its manifest's text when it starts.

use super::State;
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use sha2::Digest;
use std::path::{Path, PathBuf};
use wicket_core::Manifest;

/// The root the console may write manifests in.
pub const WRITABLE_ROOT: &str = "manifests";

/// Where a manifest's earlier versions are kept, in its root.
const HISTORY: &str = ".history";

pub fn sha256(b: &[u8]) -> String {
    hex::encode(sha2::Sha256::digest(b))
}

/// Every leaf of `v` (objects walked, arrays and scalars as leaves), by dotted path.
fn leaves(v: &Value, prefix: &str, out: &mut Vec<(String, Value)>) {
    match v {
        Value::Object(m) if !m.is_empty() => {
            for (k, x) in m {
                let p = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                leaves(x, &p, out);
            }
        }
        _ => out.push((prefix.to_string(), v.clone())),
    }
}

/// Whether `path` (dotted) was written in the YAML: it, or an array or scalar above it.
fn written(raw: &Value, path: &str) -> bool {
    let mut cur = raw;
    for k in path.split('.') {
        match cur {
            Value::Object(m) => match m.get(k) {
                Some(x) => cur = x,
                None => return false,
            },
            _ => return true,
        }
    }
    true
}

/// A manifest's every field with its effective value, marking those it didn't write (defaults).
fn fields(m: &Manifest, text: &str) -> Vec<Value> {
    let raw: Value = serde_yaml::from_str::<serde_yaml::Value>(text).ok().and_then(|y| serde_json::to_value(y).ok()).unwrap_or(Value::Null);
    let mut all = vec![];
    leaves(&serde_json::to_value(m).unwrap_or(Value::Null), "", &mut all);
    all.into_iter().map(|(path, value)| json!({ "path": path, "value": value, "default": !written(&raw, &path) })).collect()
}

/// What a manifest grants, in plain parts.
fn grants(state: &State, m: &Manifest) -> Value {
    let z = &m.zone;
    let hosts: Vec<Value> = wicket_core::splice::view(z)
        .into_iter()
        .map(|(h, i)| match i {
            wicket_core::splice::Inspection::Spliced { rule } => json!({ "host": h, "mode": "spliced", "rule": rule }),
            wicket_core::splice::Inspection::Inspected(why) => json!({ "host": h, "mode": "inspected", "why": why }),
        })
        .collect();
    let vault = wicket_proxy::vault::Vault::new(state.vault_dir.clone());
    let inject: Vec<Value> = z
        .inject
        .iter()
        .map(|i| {
            json!({ "host": i.host, "header": i.header, "secret": i.secret, "optional": i.optional,
                    "secret_set": vault.has(&i.secret), "bound_to_host": vault.allows(&i.secret, &i.host) })
        })
        .collect();
    let llm = z.llm.as_ref().map(|l| {
        json!({ "provider": l.provider, "upstream": l.upstream, "secret": l.secret, "secret_set": vault.has(&l.secret),
                "max_requests": l.max_requests, "max_output_tokens": l.max_output_tokens, "max_input_tokens": l.max_input_tokens,
                "allow_server_tools": l.allow_server_tools })
    });
    json!({
        "task": m.task,
        "agent": m.agent.as_ref().map(|a| json!({ "name": a.name, "kind": a.kind, "model": a.model, "max_turns": a.max_turns,
            "max_children": a.max_children, "idle_timeout": a.idle_timeout, "hibernate_after": a.hibernate_after,
            "remote": a.remote.as_ref().map(|r| r.name.clone()) })),
        "program": m.program.as_ref().map(|p| json!({ "name": p.name, "command": p.command })),
        "image": crate::run::manifest_image(m).map_err(|e| format!("{e:#}")),
        "isolation": format!("{:?}", z.isolation),
        "unlisted_hosts": serde_json::to_value(&z.unlisted_hosts).unwrap_or(Value::Null),
        "reach": z.reach.iter().map(|r| serde_json::to_value(r).unwrap_or(Value::Null)).collect::<Vec<_>>(),
        "forbid": z.forbid.iter().map(|r| serde_json::to_value(r).unwrap_or(Value::Null)).collect::<Vec<_>>(),
        "hosts": hosts,
        "inject": inject,
        "llm": llm,
        "volumes": z.volumes.iter().map(|v| serde_json::to_value(v).unwrap_or(Value::Null)).collect::<Vec<_>>(),
        "images": z.images,
        "accept_from": z.accept_from,
        "limits": serde_json::to_value(&z.limits).unwrap_or(Value::Null),
        "org_policy": org_effect(state, m),
    })
}

/// The installation's org policy for this manifest's zone (#51), as a mint would compile it: its
/// layer, and whether the zone's ceiling passes it. Null without an applied org policy.
fn org_effect(state: &State, m: &Manifest) -> Value {
    let d = state.data.join("policy");
    let Some(v) = std::fs::read_to_string(d.join("installed")).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) else {
        return Value::Null;
    };
    let text = std::fs::read_to_string(d.join("org.cedar")).unwrap_or_default();
    let ents = std::fs::read_to_string(d.join("org-entities.json")).unwrap_or_else(|_| "[]".into());
    let p = match wicket_policy::OrgPolicy::parse(&text, &ents) {
        Ok(p) if p.version() == v => p,
        Ok(p) => {
            return json!({ "version": v, "error": format!("org.cedar is {}, not the applied {v}: every mint is refused", p.version()) })
        }
        Err(e) => return json!({ "version": v, "error": format!("{e}") }),
    };
    let ctx = wicket_policy::MintCtx {
        zone: m.zone.name.clone(),
        tenant: m.tenant.0.clone(),
        principal: "operator:console".into(),
        depth: 0,
        groups: p.groups_of(&m.zone.name),
    };
    let layer = match p.layer(&ctx) {
        Ok(l) => l,
        Err(e) => return json!({ "version": v, "groups": ctx.groups, "error": format!("{e}") }),
    };
    let image = crate::run::manifest_image(m).unwrap_or_default();
    let mint = wicket_policy::ceiling(&m.zone, "run_check", 4_102_444_800, vec![], &[image], Some(layer.clone()));
    json!({
        "version": v,
        "groups": ctx.groups,
        "layer": serde_json::to_value(&layer).unwrap_or(Value::Null),
        "mints": mint.is_ok(),
        "refused": mint.err().map(|e| format!("{e}")),
    })
}

/// A manifest's text, checked: (parsed, or the error `wicket run` would give).
fn parse(text: &str) -> std::result::Result<Manifest, String> {
    Manifest::from_yaml(text).map_err(|e| e.to_string())
}

fn j<T: serde::Serialize>(v: &[T]) -> Vec<Value> {
    v.iter().map(|x| serde_json::to_value(x).unwrap_or(Value::Null)).collect()
}

/// What changes in authority from `old` to `new`: what each side has that the other doesn't, and
/// how `new` is wider (empty: it isn't). The widening test is the spawn one, with `old` as the
/// parent: everything `new` may do must be within what `old` may.
pub fn diff(old: Option<&Manifest>, new: &Manifest) -> Value {
    let Some(old) = old else {
        return json!({ "new": true, "widens": true, "widening": ["a new manifest: everything it grants is new"], "changes": [] });
    };
    let (o, n) = (&old.zone, &new.zone);
    let mut changes: Vec<String> = vec![];
    let set = |xs: &[Value]| xs.iter().map(|x| x.to_string()).collect::<std::collections::BTreeSet<_>>();
    let mut list = |what: &str, a: Vec<Value>, b: Vec<Value>| {
        let (a, b) = (set(&a), set(&b));
        for x in b.difference(&a) {
            changes.push(format!("+ {what} {x}"));
        }
        for x in a.difference(&b) {
            changes.push(format!("- {what} {x}"));
        }
    };
    list("reach", j(&o.reach), j(&n.reach));
    list("forbid", j(&o.forbid), j(&n.forbid));
    list("inject", j(&o.inject), j(&n.inject));
    list("volume", j(&o.volumes), j(&n.volumes));
    list("image", j(&o.images), j(&n.images));
    list("accept_from", j(&o.accept_from), j(&n.accept_from));
    let mut before_after = |what: &str, a: Value, b: Value| {
        if a != b {
            changes.push(format!("~ {what}: {a} → {b}"));
        }
    };
    before_after("isolation", json!(format!("{:?}", o.isolation)), json!(format!("{:?}", n.isolation)));
    before_after(
        "unlisted_hosts",
        serde_json::to_value(&o.unlisted_hosts).unwrap_or_default(),
        serde_json::to_value(&n.unlisted_hosts).unwrap_or_default(),
    );
    before_after("llm", serde_json::to_value(&o.llm).unwrap_or_default(), serde_json::to_value(&n.llm).unwrap_or_default());
    before_after("limits", serde_json::to_value(&o.limits).unwrap_or_default(), serde_json::to_value(&n.limits).unwrap_or_default());
    before_after("zone name", json!(o.name), json!(n.name));
    before_after("tenant", json!(old.tenant.0), json!(new.tenant.0));
    let kids = |m: &Manifest| m.agent.as_ref().map_or(0, |a| a.max_children);
    before_after("max_children", json!(kids(old)), json!(kids(new)));
    before_after("image", json!(crate::run::manifest_image(old).ok()), json!(crate::run::manifest_image(new).ok()));
    // Wider than the saved version? The spawn test, with it as the parent.
    let old_image = crate::run::manifest_image(old).unwrap_or_default();
    let new_image = crate::run::manifest_image(new).unwrap_or_default();
    let mut images = o.images.clone();
    images.push(old_image);
    let bounds = wicket_core::subset::Bounds {
        zone: o,
        images,
        llm_remaining: o.llm.as_ref().map(|l| (l.max_requests, l.max_output_tokens)),
        llm_input_remaining: o.llm.as_ref().and_then(|l| l.max_input_tokens),
        time_remaining: o.limits.timeout().unwrap_or_default(),
        child_slots: kids(old).saturating_add(1),
    };
    let ask = wicket_core::subset::Ask { zone: n, image: &new_image, max_children: kids(new) };
    let mut widening = wicket_core::subset::check(&ask, &bounds).err().unwrap_or_default();
    widening.extend(wicket_core::subset::unapprovable(n, o));
    let (of, nf) = (j(&o.forbid), j(&n.forbid));
    if of.iter().any(|f| !nf.contains(f)) {
        widening.push("a forbid rule removed: what it refused may now be asked for".into());
    }
    if old.tenant != new.tenant || o.name != n.name {
        widening.push("another tenant or zone name: a different zone's authority".into());
    }
    widening.dedup();
    json!({ "new": false, "widens": !widening.is_empty(), "widening": widening, "changes": changes })
}

/// A manifest's saved versions (newest first): `<unix seconds>-<sha256 prefix>.yaml`.
fn history(dir: &Path, name: &str) -> Vec<Value> {
    let mut v: Vec<(i64, String, String)> = std::fs::read_dir(dir.join(HISTORY).join(name))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let f = e.file_name().into_string().ok()?;
            let (t, sha) = f.strip_suffix(".yaml")?.split_once('-')?;
            Some((t.parse().ok()?, sha.to_string(), f))
        })
        .collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.0));
    v.into_iter().map(|(at, sha, file)| json!({ "version": file, "saved_before": at, "sha256_prefix": sha })).collect()
}

fn root_dir<'a>(state: &'a State, root: &str) -> Result<&'a PathBuf> {
    state.roots.iter().find(|(r, _)| r == root).map(|(_, d)| d).with_context(|| format!("no manifest root {root:?}"))
}

/// `GET /api/manifests/<root>/<name>`.
pub(super) fn view(state: &State, root: &str, name: &str) -> Result<Value> {
    let (_, bytes) = super::resolve_manifest(state, root, name)?;
    let text = String::from_utf8(bytes.clone()).context("the manifest is not UTF-8")?;
    let parsed = parse(&text);
    let writable = root == WRITABLE_ROOT;
    Ok(json!({
        "root": root,
        "name": name,
        "sha256": sha256(&bytes),
        "yaml": text,
        "valid": parsed.is_ok(),
        "error": parsed.as_ref().err(),
        "fields": parsed.as_ref().map(|m| fields(m, &text)).unwrap_or_default(),
        "grants": parsed.as_ref().ok().map(|m| grants(state, m)),
        "writable": writable,
        "history": if writable { history(root_dir(state, root)?, name) } else { vec![] },
    }))
}

/// `POST /api/manifests/check`: `{ "name", "yaml" }` against the saved version in the writable root.
pub(super) fn check(state: &State, body: &Value) -> Result<Value> {
    let name = body["name"].as_str().context("name required")?;
    let yaml = body["yaml"].as_str().context("yaml required")?;
    if yaml.len() > MAX_MANIFEST {
        bail!("the manifest is over {MAX_MANIFEST} bytes");
    }
    let saved = super::resolve_manifest(state, WRITABLE_ROOT, name).ok().and_then(|(_, b)| String::from_utf8(b).ok());
    let new = parse(yaml);
    let old = saved.as_deref().and_then(|t| parse(t).ok());
    Ok(json!({
        "valid": new.is_ok(),
        "error": new.as_ref().err(),
        "sha256": sha256(yaml.as_bytes()),
        "saved_sha256": saved.as_ref().map(|t| sha256(t.as_bytes())),
        "diff": new.as_ref().ok().map(|n| diff(old.as_ref(), n)),
        "grants": new.as_ref().ok().map(|n| grants(state, n)),
        "fields": new.as_ref().map(|m| fields(m, yaml)).unwrap_or_default(),
    }))
}

/// The most a manifest may be (bytes).
pub const MAX_MANIFEST: usize = 64 * 1024;

/// A save or restore, checked at `begin`: what is written, and the JSON the passkey signs.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Save {
    pub name: String,
    pub yaml: String,
    pub sha256: String,
    pub previous_sha256: Option<String>,
}

/// Builds a `save_manifest` (`{ name, yaml }`) or `restore_manifest` (`{ name, version }`) action.
pub(super) fn prepare(state: &State, kind: &str, body: &Value, tenant: &str) -> Result<(Save, Value)> {
    let name = body["name"].as_str().context("name required")?.to_string();
    // The name rules are resolve_manifest's; the file need not exist yet for a save.
    super::check_manifest_name(&name)?;
    let dir = root_dir(state, WRITABLE_ROOT)?;
    let (yaml, restored_from) = match kind {
        "save_manifest" => (body["yaml"].as_str().context("yaml required")?.to_string(), None),
        _ => {
            let v = body["version"].as_str().context("version required")?;
            if v.contains('/') || v.contains("..") || !v.ends_with(".yaml") {
                bail!("version {v:?}");
            }
            let p = dir.join(HISTORY).join(&name).join(v);
            (std::fs::read_to_string(&p).with_context(|| format!("no saved version {v} of {name}"))?, Some(v.to_string()))
        }
    };
    if yaml.len() > MAX_MANIFEST {
        bail!("the manifest is over {MAX_MANIFEST} bytes");
    }
    let new = parse(&yaml).map_err(|e| anyhow::anyhow!("it doesn't validate: {e}"))?;
    if new.tenant.0 != tenant {
        bail!("the manifest is for another tenant");
    }
    let saved = std::fs::read(dir.join(&name)).ok();
    let previous_sha256 = saved.as_deref().map(sha256);
    let sha = sha256(yaml.as_bytes());
    if previous_sha256.as_deref() == Some(sha.as_str()) {
        bail!("nothing changes: it is the saved version");
    }
    let old = saved.as_deref().and_then(|b| std::str::from_utf8(b).ok()).and_then(|t| parse(t).ok());
    let d = diff(old.as_ref(), &new);
    let v = json!({
        "v": 1, "action": kind, "tenant": tenant, "root": WRITABLE_ROOT, "name": name,
        "sha256": sha, "previous_sha256": previous_sha256, "restored_from": restored_from,
        "widens": d["widens"], "widening": d["widening"], "changes": d["changes"],
    });
    Ok((Save { name, yaml, sha256: sha, previous_sha256 }, v))
}

/// Applies a signed save: the file must still be the version it replaces; that version is kept in
/// the history; the new one is written in its place.
pub(super) fn apply(state: &State, s: &Save) -> Result<()> {
    let dir = root_dir(state, WRITABLE_ROOT)?.clone();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(&s.name);
    let now = std::fs::read(&path).ok();
    if now.as_deref().map(sha256) != s.previous_sha256 {
        bail!("{} changed after you were shown it; check it again", s.name);
    }
    if let Some(b) = &now {
        let h = dir.join(HISTORY).join(&s.name);
        std::fs::create_dir_all(&h)?;
        let f = h.join(format!("{}-{}.yaml", wicket_store::now(), &sha256(b)[..12]));
        std::fs::write(&f, b)?;
    }
    let tmp = dir.join(format!(".{}.new", s.name));
    std::fs::write(&tmp, &s.yaml)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}
