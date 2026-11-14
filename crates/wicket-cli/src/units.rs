//! A version's own systemd units (#165). Each build carries `deploy/systemd/` (embedded, as the
//! agent image's sources are), so whatever artifact it came in (a release archive or a bare binary)
//! a staged version knows its units.
//!
//! `wicket self update` runs as the wicket user inside wicketd, which can't (and mustn't) write
//! `/etc/systemd/system`. So on an installed host it refuses to switch to a version whose units
//! differ from the installed ones, until root applies them with that version's binary
//! (`sudo <versions>/<id>/wicket self apply-units`): installed and reloaded, never restarted (a
//! restart of wicketd stops the runs started through it). They take effect when each service next
//! restarts, so a unit change has to work with the previous version too, like an expand step of the
//! schema. A rollback is never refused over units: it only warns.
//!
//! A host without `wicketd.service` in the units directory (the development mode, a node) has no
//! installed units to compare: nothing is checked.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// This build's units: `deploy/systemd/`, every file (a test keeps the list equal to the directory).
pub const UNITS: &[(&str, &str)] = &[
    ("wicket-console.service", include_str!("../../../deploy/systemd/wicket-console.service")),
    ("wicket-follow.service", include_str!("../../../deploy/systemd/wicket-follow.service")),
    ("wicket-follow.timer", include_str!("../../../deploy/systemd/wicket-follow.timer")),
    ("wicket-reconcile.service", include_str!("../../../deploy/systemd/wicket-reconcile.service")),
    ("wicket-state.service", include_str!("../../../deploy/systemd/wicket-state.service")),
    ("wicketd.service", include_str!("../../../deploy/systemd/wicketd.service")),
];

/// Where installed units are: `$WICKET_SYSTEMD_DIR` (tests), else `/etc/systemd/system`.
pub fn systemd_dir() -> PathBuf {
    std::env::var_os("WICKET_SYSTEMD_DIR").filter(|v| !v.is_empty()).map(PathBuf::from).unwrap_or_else(|| "/etc/systemd/system".into())
}

/// This build's units, by name.
pub fn embedded() -> BTreeMap<String, String> {
    UNITS.iter().map(|(n, c)| (n.to_string(), c.to_string())).collect()
}

/// The units in `want` that are missing from `dir` or differ there; None when `dir` has no
/// installed wicket (no `wicketd.service`): nothing to compare.
pub fn differing(dir: &Path, want: &BTreeMap<String, String>) -> Option<Vec<String>> {
    if !dir.join("wicketd.service").is_file() {
        return None;
    }
    Some(want.iter().filter(|(n, c)| std::fs::read(dir.join(n)).ok().as_deref() != Some(c.as_bytes())).map(|(n, _)| n.clone()).collect())
}

/// The units the staged build at `bin` carries (`self units`); None for a build from before #165,
/// which can't say.
pub fn of_build(bin: &Path, probe: &Path) -> Result<Option<BTreeMap<String, String>>> {
    let out = std::process::Command::new(bin)
        .args(["self", "units"])
        .env("WICKET_HOME", probe)
        .env_remove("WICKET_DAEMON_SOCKET")
        .output()
        .with_context(|| format!("running {}", bin.display()))?;
    let _ = std::fs::remove_dir_all(probe);
    if !out.status.success() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&out.stdout).context("the build's `self units`")?))
}

/// Why an update didn't switch: the staged version's units aren't installed yet. Not a failure of
/// the build (`self follow` tries it again once they are).
#[derive(Debug)]
pub struct UnitsPending {
    pub version: String,
    pub units: Vec<String>,
    pub dir: PathBuf,
    pub binary: PathBuf,
}

impl std::fmt::Display for UnitsPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "refused: version {}'s systemd units differ from those installed in {} ({}). Apply them first, as root: `sudo {} self apply-units`; then run the update again (they take effect as each service next restarts)",
            self.version,
            self.dir.display(),
            self.units.join(", "),
            self.binary.display()
        )
    }
}

impl std::error::Error for UnitsPending {}

/// `wicket self units`: this build's units, as JSON (name → contents).
pub fn print() -> Result<()> {
    println!("{}", serde_json::to_string(&embedded())?);
    Ok(())
}

/// `wicket self apply-units`: installs this build's units into `dir` (default the systemd one,
/// which needs root) where they differ, then `systemctl daemon-reload`. Restarts nothing.
pub fn apply(dir: Option<PathBuf>) -> Result<()> {
    let default = dir.is_none();
    let dir = dir.unwrap_or_else(systemd_dir);
    // SAFETY: geteuid has no preconditions.
    if default && unsafe { libc::geteuid() } != 0 {
        bail!("installing systemd units needs root: sudo {} self apply-units", std::env::current_exe()?.display());
    }
    if !dir.is_dir() {
        bail!("{} is not a directory", dir.display());
    }
    let want = embedded();
    let mut changed = vec![];
    let mut added = vec![];
    for (name, contents) in &want {
        let p = dir.join(name);
        let old = std::fs::read(&p).ok();
        if old.as_deref() == Some(contents.as_bytes()) {
            continue;
        }
        let tmp = dir.join(format!(".{name}.wicket-new"));
        std::fs::write(&tmp, contents).with_context(|| tmp.display().to_string())?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))?;
        std::fs::rename(&tmp, &p).with_context(|| p.display().to_string())?;
        if old.is_some() { &mut changed } else { &mut added }.push(name.clone());
    }
    if changed.is_empty() && added.is_empty() {
        println!("[self] the units in {} are this build's already", dir.display());
        return Ok(());
    }
    for n in &changed {
        println!("[self] updated {}", dir.join(n).display());
    }
    for n in &added {
        println!("[self] added {}", dir.join(n).display());
    }
    if default && Path::new("/run/systemd/system").is_dir() {
        let st = std::process::Command::new("systemctl").arg("daemon-reload").status().context("running systemctl daemon-reload")?;
        if !st.success() {
            bail!("systemctl daemon-reload failed");
        }
        println!("[self] systemd reloaded");
    }
    if !changed.is_empty() {
        println!(
            "[self] each takes effect when its service next restarts (systemctl restart {}; restarting wicketd stops the runs started through it). Nothing was restarted",
            changed.iter().map(|n| n.trim_end_matches(".service")).collect::<Vec<_>>().join(" ")
        );
    }
    if !added.is_empty() {
        println!("[self] new units are installed, not enabled (see deploy/install.sh for which it enables)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_units_are_deploy_systemd() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/systemd");
        let mut names: Vec<String> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        assert_eq!(names, embedded().keys().cloned().collect::<Vec<_>>(), "add the new unit to UNITS");
        for (n, c) in UNITS {
            assert_eq!(std::fs::read_to_string(dir.join(n)).unwrap(), *c);
        }
    }

    #[test]
    fn differing_units_are_found_and_applied() {
        let d = std::env::temp_dir().join(format!("wicket-units-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let _clean = Remove(d.clone());
        let d = Dir(d);
        let want = embedded();
        // No wicketd.service: not an installed host, nothing compared.
        assert_eq!(differing(d.path(), &want), None);
        apply(Some(d.path().to_path_buf())).unwrap();
        assert_eq!(differing(d.path(), &want), Some(vec![]));
        std::fs::write(d.path().join("wicketd.service"), "[Service]\nExecStart=/bin/true\n").unwrap();
        std::fs::remove_file(d.path().join("wicket-follow.timer")).unwrap();
        assert_eq!(differing(d.path(), &want), Some(vec!["wicket-follow.timer".to_string(), "wicketd.service".to_string()]));
        apply(Some(d.path().to_path_buf())).unwrap();
        assert_eq!(differing(d.path(), &want), Some(vec![]));
        let mode = std::fs::metadata(d.path().join("wicketd.service")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    struct Dir(PathBuf);
    impl Dir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    struct Remove(PathBuf);
    impl Drop for Remove {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
