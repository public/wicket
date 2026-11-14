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
//! Only units that run the versions root being updated are compared: the installed
//! `wicketd.service`'s `ExecStart` binary must resolve into it (`/usr/local/bin/wicket` links to
//! `<root>/current/wicket`). A host without one (a node), or a development-mode installation on a
//! host that also has a system install, has no units of its own to compare: nothing is checked.

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

/// Whether the units in `dir` run the versions under `root`: `wicketd.service`'s `ExecStart`
/// binary resolves to `<root>/<id>/wicket`.
pub fn run_versions(dir: &Path, root: &Path) -> bool {
    let Ok(unit) = std::fs::read_to_string(dir.join("wicketd.service")) else { return false };
    let Some(bin) = unit.lines().find_map(|l| l.trim().strip_prefix("ExecStart=")).and_then(|c| c.split_whitespace().next()) else {
        return false;
    };
    let bin = bin.trim_start_matches(['-', '@', '+', '!', ':']);
    let (Ok(bin), Ok(root)) = (std::fs::canonicalize(bin), std::fs::canonicalize(root)) else { return false };
    bin.parent().and_then(Path::parent) == Some(root.as_path())
}

/// The units in `want` that are missing from `dir` or differ there; None when the units in `dir`
/// don't run the versions under `root` ([`run_versions`]): nothing to compare.
pub fn differing(dir: &Path, root: &Path, want: &BTreeMap<String, String>) -> Option<Vec<String>> {
    if !run_versions(dir, root) {
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
        // A versions root, and the link the units run (as /usr/local/bin/wicket is).
        let (units, root) = (d.path().join("units"), d.path().join("versions"));
        std::fs::create_dir_all(root.join("aaaaaaaaaaaa")).unwrap();
        std::fs::create_dir_all(&units).unwrap();
        std::fs::write(root.join("aaaaaaaaaaaa/wicket"), "").unwrap();
        std::os::unix::fs::symlink("aaaaaaaaaaaa", root.join("current")).unwrap();
        let link = d.path().join("bin-wicket");
        std::os::unix::fs::symlink(root.join("current/wicket"), &link).unwrap();
        let ours = |unit: &str| unit.replace("/usr/local/bin/wicket", &link.display().to_string());
        let want: BTreeMap<String, String> = embedded().into_iter().map(|(n, c)| (n, ours(&c))).collect();
        // No wicketd.service: not an installed host, nothing compared.
        assert_eq!(differing(&units, &root, &want), None);
        apply(Some(units.clone())).unwrap();
        // The embedded units run /usr/local/bin/wicket, not this root: not ours to compare.
        assert_eq!(differing(&units, &root, &want), None);
        for (n, c) in &want {
            std::fs::write(units.join(n), c).unwrap();
        }
        assert_eq!(differing(&units, &root, &want), Some(vec![]));
        std::fs::write(units.join("wicketd.service"), ours("[Service]\nExecStart=/usr/local/bin/wicket daemon --other\n")).unwrap();
        std::fs::remove_file(units.join("wicket-follow.timer")).unwrap();
        assert_eq!(differing(&units, &root, &want), Some(vec!["wicket-follow.timer".to_string(), "wicketd.service".to_string()]));
        // Another versions root (a development-mode installation on the same host): not compared.
        std::fs::create_dir_all(d.path().join("other")).unwrap();
        assert_eq!(differing(&units, &d.path().join("other"), &want), None);
        apply(Some(units.clone())).unwrap();
        let mode = std::fs::metadata(units.join("wicketd.service")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        assert_eq!(std::fs::read_to_string(units.join("wicket-follow.timer")).unwrap(), embedded()["wicket-follow.timer"]);
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
