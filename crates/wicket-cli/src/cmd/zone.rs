//! `wicket zone`: a manifest's zone, explained, and its images pinned.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Zone { cmd: Some(ZoneCmd::Pin { manifest, dry_run }), .. } => pin::pin(&manifest, dry_run),
        Cmd::Zone { manifest, json, .. } => {
            let manifest = manifest.context("a manifest: wicket zone MANIFEST, or wicket zone pin MANIFEST")?;
            let m = wicket_core::Manifest::from_yaml(
                &std::fs::read_to_string(&manifest).with_context(|| format!("reading {}", manifest.display()))?,
            )?;
            print!("{}", zone_view(&m.zone, json));
            Ok(())
        }
        _ => unreachable!("dispatched to the wrong command group"),
    }
}

#[derive(Subcommand)]
pub enum ZoneCmd {
    /// Rewrite a manifest's image tags (zone.images, agent.image, program.image) to the digests they
    /// point to now, in place, keeping the rest of the file (#192).
    Pin {
        manifest: PathBuf,
        /// Say what would change; write nothing.
        #[arg(long)]
        dry_run: bool,
    },
}

/// The zone view (`wicket zone`): each host the zone's reach names, spliced or inspected, and why.
/// What the zone view says about wildcard reach rules (#20): any name under one is resolved on the
/// host, which makes the names a narrow channel out of the box.
pub(crate) fn wildcard_warnings(zone: &wicket_core::ZoneSpec) -> Vec<String> {
    zone.wildcard_reach()
        .iter()
        .map(|w| {
            format!(
                "wildcard reach rule {w}: any name under it that the agent makes up is resolved on the host, a narrow DNS channel out of the box. \
                 wicket resolves a name only after a request to it is allowed, and at most {} names under it per run (wildcards.max_names). \
                 In a sensitive zone, name each host exactly and set wildcards: {{ forbid: true }}",
                zone.wildcards.max_names
            )
        })
        .collect()
}

pub(crate) fn zone_view(zone: &wicket_core::ZoneSpec, json: bool) -> String {
    use wicket_core::splice::Inspection;
    let rows = wicket_core::splice::view(zone);
    let warnings = wildcard_warnings(zone);
    if json {
        let v: Vec<serde_json::Value> = rows
            .iter()
            .map(|(h, i)| match i {
                Inspection::Spliced { rule } => serde_json::json!({ "host": h, "mode": "spliced", "rule": rule }),
                Inspection::Inspected(why) => serde_json::json!({ "host": h, "mode": "inspected", "why": why }),
            })
            .collect();
        return format!(
            "{}\n",
            serde_json::to_string_pretty(&serde_json::json!({ "zone": zone.name, "hosts": v, "warnings": warnings })).unwrap_or_default()
        );
    }
    let mut out = format!("zone {}: egress over HTTPS (HTTP/3 is always terminated and inspected)\n", zone.name);
    let w = rows.iter().map(|(h, _)| h.len()).max().unwrap_or(0);
    for (h, i) in &rows {
        match i {
            Inspection::Spliced { rule } => out.push_str(&format!(
                "  {h:<w$}  SPLICED    reach rule {rule} allows every method and path: decided at connect, not inspected\n"
            )),
            Inspection::Inspected(why) => out.push_str(&format!("  {h:<w$}  INSPECTED  {why}\n")),
        }
    }
    if rows.iter().any(|(_, i)| i.is_spliced()) {
        out.push_str("  Spliced on the control host, and on a node while its policy is fresh (else inspected there).\n");
        out.push_str("  Spliced hosts get one audit row per connection, no per-request decisions or header filtering,\n");
        out.push_str("  and on a shared CDN may reach other sites behind it. Add a forbid rule to inspect one.\n");
    }
    if rows.is_empty() {
        out.push_str("  (reach names no hosts)\n");
    }
    for w in &warnings {
        out.push_str(&format!("  WARNING: {w}.\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    fn zone(body: &str) -> wicket_core::ZoneSpec {
        wicket_core::Manifest::from_yaml(&format!("task: t\nagent: {{ name: a }}\nzone: {{ name: z, llm: {{}}, {body} }}\n")).unwrap().zone
    }

    /// #20: the zone view warns about each wildcard reach rule, in text and JSON, and not otherwise.
    #[test]
    fn the_zone_view_warns_about_wildcards() {
        let z = zone("reach: [{ host: api.example.com }, { host: '*.cdn.example' }], wildcards: { max_names: 5 }");
        let text = super::zone_view(&z, false);
        assert!(text.contains("WARNING: wildcard reach rule *.cdn.example") && text.contains("at most 5 names"), "{text}");
        assert!(!text.contains("WARNING: wildcard reach rule api.example.com"), "{text}");
        let json: serde_json::Value = serde_json::from_str(&super::zone_view(&z, true)).unwrap();
        assert_eq!(json["warnings"].as_array().map(|a| a.len()), Some(1), "{json}");
        let exact = super::zone_view(&zone("reach: [{ host: api.example.com }]"), false);
        assert!(!exact.contains("WARNING"), "{exact}");
    }
}
