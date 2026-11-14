//! Installation settings: decisions that belong to the installation's owner, not to a manifest.
//! `/etc/wicket/wicket.yaml` (root's, like the daemon's policy), or `$WICKET_CONFIG` (development and
//! tests). A missing file means every setting's default; a file that can't be read or parsed stops
//! the run, so a setting meant to allow something never silently allows it, nor the reverse.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::PathBuf;
use wicket_core::Manifest;

pub const PATH: &str = "/etc/wicket/wicket.yaml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// The Claude adapter's (`acp`): its settings and their check live with the adapter.
    #[serde(default)]
    pub acp: wicket_agent::acp::ClaudeAdapterSettings,
}

pub fn path() -> PathBuf {
    std::env::var_os("WICKET_CONFIG").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(PATH))
}

pub fn load() -> Result<Settings> {
    load_from(&path())
}

fn load_from(p: &std::path::Path) -> Result<Settings> {
    match std::fs::read_to_string(p) {
        Ok(s) if s.trim().is_empty() => Ok(Settings::default()),
        Ok(s) => serde_yaml::from_str(&s).with_context(|| format!("the installation settings {}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(e) => Err(e).with_context(|| format!("reading the installation settings {}", p.display())),
    }
}

/// Refuses, at run start, what the installation's settings don't allow a manifest to do (#66).
pub fn check_run(m: &Manifest, s: &Settings) -> Result<()> {
    wicket_agent::acp::check_claude_adapter(m, &s.acp, &path().display().to_string()).map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(agent: &str, llm: bool) -> Manifest {
        Manifest::from_yaml(&format!("task: t\nagent: {agent}\nzone: {{name: z{}}}", if llm { ", llm: {}" } else { "" })).unwrap()
    }

    fn allowed(yes: bool) -> Settings {
        Settings { acp: wicket_agent::acp::ClaudeAdapterSettings { allow_subscription_backed_claude_adapter: yes } }
    }

    #[test]
    fn the_claude_adapter_on_a_subscription_is_refused_unless_the_installation_allows_it() {
        let claude = manifest("{name: a, kind: acp, acp: {command: [claude-agent-acp], profile: claude-agent-acp}}", true);
        let e = check_run(&claude, &Settings::default()).unwrap_err().to_string();
        assert!(e.contains("acp.allow_subscription_backed_claude_adapter: true") && e.contains("kind: claude-code"), "{e}");
        assert!(check_run(&claude, &allowed(false)).is_err());
        // The owner's opt-in.
        assert!(check_run(&claude, &allowed(true)).is_ok());
        // The adapter by its command alone must use the profile (and so this check).
        let bare = manifest("{name: a, kind: acp, acp: {command: [npx, '@agentclientprotocol/claude-agent-acp@0.104.1']}}", false);
        assert!(check_run(&bare, &allowed(true)).unwrap_err().to_string().contains("profile: claude-agent-acp"));
        // Nothing else is affected.
        assert!(
            check_run(&manifest("{name: a, kind: acp, acp: {command: [gemini, --experimental-acp]}}", false), &Settings::default()).is_ok()
        );
        assert!(check_run(&manifest("{name: a}", true), &Settings::default()).is_ok());
    }

    #[test]
    fn the_settings_file_defaults_to_no_and_a_bad_one_stops_the_run() {
        let d = std::env::temp_dir().join(format!("wicket-settings-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("wicket.yaml");
        let read = |body: Option<&str>| {
            let _ = std::fs::remove_file(&f);
            if let Some(b) = body {
                std::fs::write(&f, b).unwrap();
            }
            load_from(&f)
        };
        assert!(!read(None).unwrap().acp.allow_subscription_backed_claude_adapter);
        assert!(!read(Some("")).unwrap().acp.allow_subscription_backed_claude_adapter);
        assert!(
            read(Some("acp:\n  allow_subscription_backed_claude_adapter: true\n")).unwrap().acp.allow_subscription_backed_claude_adapter
        );
        assert!(read(Some("acp:\n  allow_subscription_backed_claude_adaptor: true\n")).is_err(), "a misspelt key is an error, not a no");
        assert!(read(Some("acp: yes\n")).is_err());
        let _ = std::fs::remove_dir_all(d);
    }
}
