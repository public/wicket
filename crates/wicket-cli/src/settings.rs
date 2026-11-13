//! Installation settings: decisions that belong to the installation's owner, not to a manifest.
//! `/etc/wicket/wicket.yaml` (root's, like the daemon's policy), or `$WICKET_CONFIG` (development and
//! tests). A missing file means every setting's default; a file that can't be read or parsed stops
//! the run, so a setting meant to allow something never silently allows it, nor the reverse.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::PathBuf;
use wicket_core::Manifest;

pub const PATH: &str = "/etc/wicket/wicket.yaml";

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default)]
    pub acp: AcpSettings,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpSettings {
    /// Whether Claude Code may run through its ACP adapter (`claude-agent-acp`, which drives the
    /// `claude` binary through the Claude Agent SDK) on the installation's Claude subscription. The
    /// owner's reading of the subscription's terms (research 21 §2.6). Default: no.
    #[serde(default)]
    pub allow_subscription_backed_claude_adapter: bool,
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
    let Some(spec) = m.agent.as_ref().filter(|a| a.kind == "acp").and_then(|a| a.acp.as_ref()) else { return Ok(()) };
    if !wicket_agent::acp::is_claude_adapter(spec) {
        return Ok(());
    }
    // Claude Code through its adapter goes through wicket's profile, and so through the check below.
    if spec.profile.as_deref() != Some("claude-agent-acp") {
        bail!("agent.acp.command starts Claude Code's ACP adapter: set agent.acp.profile: claude-agent-acp");
    }
    // The zone's model route is a Claude subscription (wicket never uses an API key).
    let subscription = m.zone.llm.as_ref().is_some_and(|l| l.provider == "anthropic");
    if subscription && !s.acp.allow_subscription_backed_claude_adapter {
        bail!(
            "this zone runs Claude Code through its ACP adapter (the Claude Agent SDK) on the Claude subscription in zone.llm, \
             which this installation doesn't allow. Whether the subscription may back the adapter is the owner's decision; \
             to allow it, set acp.allow_subscription_backed_claude_adapter: true in {}. Meanwhile, run Claude Code as kind: claude-code",
            path().display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(agent: &str, llm: bool) -> Manifest {
        Manifest::from_yaml(&format!("task: t\nagent: {agent}\nzone: {{name: z{}}}", if llm { ", llm: {}" } else { "" })).unwrap()
    }

    fn allowed(yes: bool) -> Settings {
        Settings { acp: AcpSettings { allow_subscription_backed_claude_adapter: yes } }
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
