//! `wicket manifest` (#713): the console's manifest viewer and editor (#172), from the host.
//!
//! - **The same views.** `list`, `show` and `check` print what the console's dashboard,
//!   `/api/manifests/<root>/<name>` and `/api/manifests/check` return ([`manifests`]), `--json`
//!   whole.
//! - **The same save.** `save` and `restore` write only the installation's `manifests` root, as
//!   the console does: [`manifests::prepare`] checks the new version (it validates, is this
//!   tenant's, and changes something) and says what it adds, removes and widens against the saved
//!   one; [`manifests::save_and_record`] keeps the version it replaces in the history, writes the
//!   new one if the file is still what was shown, and audits `manifest.saved` with the operator.
//!   `--dry-run` shows the change and writes nothing.

use crate::serve::manifests::{self, Place};
use crate::*;
use serde_json::{json, Value};

#[derive(Subcommand)]
pub enum ManifestCmd {
    /// The manifests runs can be started from, in every root: each one's agent or program, zone,
    /// image, and whether it validates.
    List {
        /// Print JSON (docs/reference/cli.md, "Output for scripts"), as the console's dashboard lists them.
        #[arg(long)]
        json: bool,
    },
    /// One manifest: whether it validates, its image, the hosts it reaches and how (inspected or
    /// spliced), the secrets it injects by name and whether the vault has them, the org policy's
    /// effect on its zone, and, in the `manifests` root, its saved versions.
    Show {
        /// `<root>/<name>` (e.g. `examples/claude.yaml`), or a name in the `manifests` root.
        manifest: String,
        /// Print JSON: every field with its effective value and whether it was written, and the rest.
        #[arg(long)]
        json: bool,
    },
    /// Check an edited manifest against the saved version of `name` in the `manifests` root: whether
    /// it validates, and what it adds, removes and widens. Writes nothing.
    Check {
        /// The name it would be saved as (e.g. `worker.yaml`).
        name: String,
        /// The edited manifest (YAML).
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Save a manifest into the `manifests` root as `name`, as the console's editor does: the version
    /// it replaces is kept in its history, and the save is audited with what it widens.
    Save {
        name: String,
        /// The new version (YAML).
        #[arg(long)]
        file: PathBuf,
        /// Show what it changes; write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Restore a saved version of a manifest in the `manifests` root (`wicket manifest show` lists
    /// them), as a save: the current version is kept in the history too.
    Restore {
        name: String,
        /// The version, as `show` lists it (`<unix seconds>-<sha256 prefix>.yaml`).
        version: String,
        /// Show what it changes; write nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

fn with_place<T>(f: impl FnOnce(&Place) -> Result<T>) -> Result<T> {
    let roots = crate::serve::manifest_roots();
    let (data, vault) = (wicket_home::data_dir(), wicket_proxy::vault::Vault::default_dir());
    f(&Place { roots: &roots, data: &data, vault_dir: &vault })
}

/// Text from a view, cleaned for a terminal: a manifest's words are an author's, not wicket's.
fn s(v: &Value) -> String {
    match v {
        Value::String(s) => wicket_agent::clip(s, 300),
        Value::Null => "-".into(),
        v => wicket_agent::clip(&v.to_string(), 300),
    }
}

/// `root/name`, or a name in the writable root.
fn split(manifest: &str) -> (&str, &str) {
    manifest.split_once('/').unwrap_or((manifests::WRITABLE_ROOT, manifest))
}

/// What a save, a restore or a check changes against the saved version, one line each.
pub(crate) fn diff_text(d: &Value) -> String {
    let mut out = String::new();
    if d["new"] == true {
        out.push_str("  a new manifest: everything it grants is new\n");
        return out;
    }
    let changes = d["changes"].as_array().map(Vec::as_slice).unwrap_or_default();
    if changes.is_empty() {
        out.push_str("  no change to its authority\n");
    }
    for c in changes {
        out.push_str(&format!("  {}\n", s(c)));
    }
    if d["widens"] == true {
        out.push_str("  WIDENS what it grants:\n");
        for w in d["widening"].as_array().into_iter().flatten() {
            out.push_str(&format!("    {}\n", s(w)));
        }
    }
    out
}

/// One line for `wicket manifest list`.
pub(crate) fn line(m: &Value) -> String {
    let what = match (&m["agent"], &m["program"]) {
        (Value::String(a), _) => format!("agent {}", wicket_agent::clip(a, 80)),
        (_, Value::String(p)) => format!("program {}", wicket_agent::clip(p, 80)),
        _ => "-".into(),
    };
    let image = match (&m["image"], &m["image_error"]) {
        (Value::String(i), _) => wicket_agent::clip(i, 120),
        (_, Value::String(e)) => format!("no image: {}", wicket_agent::clip(e, 120)),
        _ => "-".into(),
    };
    let valid = if m["valid"] == true { "" } else { "  (doesn't validate)" };
    format!("{}/{}  {what}  zone {}  {image}{valid}", s(&m["root"]), s(&m["name"]), s(&m["zone"]))
}

/// What `wicket manifest show` prints without --json.
pub(crate) fn show_text(v: &Value) -> String {
    let mut out = format!("{}/{}  sha256 {}\n", s(&v["root"]), s(&v["name"]), s(&v["sha256"]));
    if v["valid"] != true {
        out.push_str(&format!("  doesn't validate: {}\n", s(&v["error"])));
        return out;
    }
    let g = &v["grants"];
    let image = match (&g["image"]["Ok"], &g["image"]["Err"]) {
        (Value::String(_), _) => s(&g["image"]["Ok"]),
        (_, Value::String(_)) => format!("none: {}", s(&g["image"]["Err"])),
        _ => "-".into(),
    };
    out.push_str(&format!("  image: {image}\n"));
    out.push_str(&format!("  isolation {}, unlisted hosts {}\n", s(&g["isolation"]), s(&g["unlisted_hosts"])));
    for h in g["hosts"].as_array().into_iter().flatten() {
        let how = if h["mode"] == "spliced" { "spliced".to_string() } else { format!("inspected ({})", s(&h["why"])) };
        out.push_str(&format!("  host {}: {how}\n", s(&h["host"])));
    }
    for i in g["inject"].as_array().into_iter().flatten() {
        let set = if i["secret_set"] == true { "set" } else { "NOT SET" };
        let bound = if i["bound_to_host"] == true { "" } else { ", not bound to that host" };
        out.push_str(&format!("  injects secret {} ({set}{bound}) into {} on {}\n", s(&i["secret"]), s(&i["header"]), s(&i["host"])));
    }
    if let Some(l) = g["llm"].as_object() {
        let set = if l["secret_set"] == true { "set" } else { "NOT SET" };
        out.push_str(&format!("  model: {} via secret {} ({set})\n", s(&l["provider"]), s(&l["secret"])));
    }
    match g["org_policy"].as_object() {
        None => out.push_str("  org policy: none applied\n"),
        Some(p) if p.get("error").is_some_and(|e| !e.is_null()) => out.push_str(&format!("  org policy {}: {}\n", s(&p["version"]), s(&p["error"]))),
        Some(p) => out.push_str(&format!(
            "  org policy {}: {}\n",
            s(&p["version"]),
            if p["mints"] == true { "its zone mints".to_string() } else { format!("refused: {}", s(&p["refused"])) }
        )),
    }
    for h in v["history"].as_array().into_iter().flatten() {
        out.push_str(&format!("  saved version {} (replaced at {})\n", s(&h["version"]), wicket_core::time::unix_rfc3339(h["saved_before"].as_i64().unwrap_or(0))));
    }
    out
}

/// `save` and `restore`: what it changes, then (unless `dry_run`) the write and its record.
fn save(kind: &str, body: Value, dry_run: bool) -> Result<()> {
    let t = TenantId::single();
    with_place(|p| {
        let (save, action) = manifests::prepare(p, kind, &body, &t.0).map_err(|e| wicket_home::exit::refused(format!("{e:#}")))?;
        let what = if kind == "restore_manifest" { "restoring" } else { "saving" };
        print!("{what} {}/{} (sha256 {}…):\n{}", manifests::WRITABLE_ROOT, save.name, &save.sha256[..12], diff_text(&action));
        if dry_run {
            println!("(dry run: nothing written)");
            return Ok(());
        }
        let l = Ledger::open(&ledger_path())?;
        manifests::save_and_record(p, &l, &t, &save, &action, &operator(), json!({ "via": "cli" }))?;
        println!("saved; the previous version is kept in its history");
        Ok(())
    })
}

pub async fn dispatch(c: ManifestCmd) -> Result<()> {
    match c {
        ManifestCmd::List { json } => {
            let rows = with_place(|p| Ok(manifests::list(p.roots)))?;
            if json {
                return super::print_json(&rows.into());
            }
            if rows.is_empty() {
                println!("no manifests");
            }
            for m in &rows {
                println!("{}", line(m));
            }
            Ok(())
        }
        ManifestCmd::Show { manifest, json } => {
            let (root, name) = split(&manifest);
            let v = with_place(|p| manifests::view(p, root, name)).map_err(|e| wicket_home::exit::not_found(format!("{e:#}")))?;
            if json {
                return super::print_json(&v);
            }
            print!("{}", show_text(&v));
            Ok(())
        }
        ManifestCmd::Check { name, file, json } => {
            let yaml = std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            let v = with_place(|p| manifests::check(p, &json!({ "name": name, "yaml": yaml })))?;
            if json {
                return super::print_json(&v);
            }
            if v["valid"] != true {
                return Err(wicket_home::exit::refused(format!("it doesn't validate: {}", s(&v["error"]))));
            }
            print!("{name} against the saved version:\n{}", diff_text(&v["diff"]));
            Ok(())
        }
        ManifestCmd::Save { name, file, dry_run } => {
            let yaml = std::fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            save("save_manifest", json!({ "name": name, "yaml": yaml }), dry_run)
        }
        ManifestCmd::Restore { name, version, dry_run } => save("restore_manifest", json!({ "name": name, "version": version }), dry_run),
    }
}
