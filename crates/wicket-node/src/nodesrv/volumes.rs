//! What becomes of a box's volumes on its node (#377). A volume the zone keeps lives under the node's
//! `volumes/<tenant>/<zone>/<name>`, shared by the zone's runs, and is deleted once it has gone
//! unused for its retention (if it has one). Any other volume is the run's own cache, under
//! `runs/<run>/cache/<name>`: deleted when the run's work is collected (the control host's
//! `Forget`), or its retention after the run ended if it never is. A run's workspace is never
//! deleted here: only caches and expired kept volumes.
//!
//! Each volume's lifecycle is recorded beside it: a kept volume's in `.<name>.life.json` next to
//! its directory, a run's caches' in `runs/<run>/cache/.life.json`. A volume with no record (from a
//! control host before #377) is kept forever, as volumes were before.

use crate::chan::{BoxStart, VolumeLife};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A run's cache volumes, under its directory.
pub(super) const CACHE_DIR: &str = "cache";
const CACHE_LIFE: &str = ".life.json";

/// A volume's (or a run's caches') record.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub(super) struct Life {
    /// How long it is kept unused (a kept volume), or after its run ended (caches); None: forever.
    pub retention_secs: Option<u64>,
    /// When a box last had it (Unix ms).
    pub used_ms: i64,
    /// Caches: when the run's box ended.
    #[serde(default)]
    pub ended_ms: Option<i64>,
}

fn read(p: &Path) -> Option<Life> {
    serde_json::from_slice(&std::fs::read(p).ok()?).ok()
}

fn write(p: &Path, l: &Life) {
    let _ = wicket_chan::files::replace(p, "tmp", &serde_json::to_vec(l).unwrap_or_default());
}

fn life_of<'a>(bs: &'a BoxStart, name: &str) -> Option<&'a VolumeLife> {
    bs.volume_life.as_ref()?.iter().find(|l| l.name == name)
}

/// Where a box's volume `name` lives: `kept` is the zone's directory for it, `run_dir` the run's.
pub(super) fn dir_for(bs: &BoxStart, name: &str, kept: PathBuf, run_dir: &Path) -> PathBuf {
    match life_of(bs, name) {
        Some(l) if !l.keep => run_dir.join(CACHE_DIR).join(name),
        _ => kept,
    }
}

/// The record of the volume at `dir` (as [`dir_for`] placed it).
fn record_path(bs: &BoxStart, name: &str, dir: &Path) -> Option<PathBuf> {
    let l = life_of(bs, name)?;
    let parent = dir.parent()?;
    Some(match l.keep {
        true => parent.join(format!(".{name}.life.json")),
        false => parent.join(CACHE_LIFE),
    })
}

/// A box has volume `name` at `dir` (as it starts, and as it ends): its record says so.
pub(super) fn used(bs: &BoxStart, name: &str, dir: &Path, now_ms: i64) {
    let (Some(l), Some(p)) = (life_of(bs, name), record_path(bs, name, dir)) else { return };
    let mut rec = read(&p).unwrap_or_default();
    rec.used_ms = now_ms;
    rec.retention_secs = match l.keep {
        true => l.retention_secs,
        // A run's caches are kept as long as the longest-kept of them.
        false => rec.retention_secs.max(l.retention_secs),
    };
    if !l.keep {
        rec.ended_ms = None;
    }
    write(&p, &rec);
}

/// The run's box has ended: its caches' retention starts now, and its kept volumes were last used.
pub(super) fn box_ended(bs: &BoxStart, kept_root: &Path, run_dir: &Path, now_ms: i64) {
    for (name, _) in &bs.volumes {
        let kept = kept_root.join(&bs.tenant).join(&bs.zone).join(name);
        let dir = dir_for(bs, name, kept, run_dir);
        used(bs, name, &dir, now_ms);
    }
    let p = run_dir.join(CACHE_DIR).join(CACHE_LIFE);
    if let Some(mut rec) = read(&p) {
        rec.ended_ms = Some(now_ms);
        write(&p, &rec);
    }
}

/// Deletes a run's caches (its work collected).
pub(super) fn drop_caches(run_dir: &Path) -> bool {
    let d = run_dir.join(CACHE_DIR);
    d.is_dir() && std::fs::remove_dir_all(&d).is_ok()
}

/// What the sweep deleted: the directory, and why.
pub(super) type Swept = Vec<(PathBuf, String)>;

/// Deletes what has outlived its retention at `now_ms`: the caches of runs not in `running` that
/// ended more than their retention ago, and kept volumes under `kept_root` unused for longer than
/// theirs and not in `in_use` (the directories boxes now running have mounted).
pub(super) fn sweep(kept_root: &Path, runs_root: &Path, running: &dyn Fn(&str) -> bool, in_use: &[PathBuf], now_ms: i64) -> Swept {
    let mut out = Vec::new();
    let past = |since: i64, secs: Option<u64>| secs.is_some_and(|s| now_ms - since > (s as i64).saturating_mul(1000));
    for run in std::fs::read_dir(runs_root).into_iter().flatten().flatten() {
        let name = run.file_name().to_string_lossy().into_owned();
        let cache = run.path().join(CACHE_DIR);
        let Some(rec) = read(&cache.join(CACHE_LIFE)) else { continue };
        if running(&name) {
            continue;
        }
        if let Some(ended) = rec.ended_ms.filter(|e| past(*e, rec.retention_secs)) {
            if std::fs::remove_dir_all(&cache).is_ok() {
                out.push((cache, format!("run {name}'s cache, {} h after the run ended uncollected", (now_ms - ended) / 3_600_000)));
            }
        }
    }
    for tenant in std::fs::read_dir(kept_root).into_iter().flatten().flatten() {
        for zone in std::fs::read_dir(tenant.path()).into_iter().flatten().flatten() {
            for f in std::fs::read_dir(zone.path()).into_iter().flatten().flatten() {
                let file = f.file_name().to_string_lossy().into_owned();
                let Some(vol) = file.strip_prefix('.').and_then(|n| n.strip_suffix(".life.json")) else { continue };
                let dir = zone.path().join(vol);
                let Some(rec) = read(&f.path()) else { continue };
                if in_use.contains(&dir) || !past(rec.used_ms, rec.retention_secs) {
                    continue;
                }
                if std::fs::remove_dir_all(&dir).is_ok() || !dir.exists() {
                    let _ = std::fs::remove_file(f.path());
                    out.push((dir, format!("kept volume unused for {} h, past its retention", (now_ms - rec.used_ms) / 3_600_000)));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(lives: Option<Vec<VolumeLife>>) -> BoxStart {
        let mut r = super::super::tests::fake_record("run_a").start;
        r.tenant = "t0".into();
        r.zone = "z".into();
        r.volumes = vec![("cache".into(), "/volumes/cache".into()), ("data".into(), "/volumes/data".into())];
        r.volume_life = lives;
        r
    }

    fn lives() -> Option<Vec<VolumeLife>> {
        Some(vec![
            VolumeLife { name: "cache".into(), keep: false, retention_secs: Some(3600) },
            VolumeLife { name: "data".into(), keep: true, retention_secs: Some(7200) },
        ])
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-volumes-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A cache is the run's and goes once its retention after the run's end has passed (never while
    /// the run runs); a kept volume is the zone's and goes once unused past its retention.
    #[test]
    fn caches_and_kept_volumes_outlive_only_their_retention() {
        let d = tmp("sweep");
        let (kept_root, runs) = (d.join("volumes"), d.join("runs"));
        let run_dir = runs.join("run_a");
        let bs = start(lives());
        let mut mounted = vec![];
        for (name, _) in &bs.volumes {
            let dir = dir_for(&bs, name, kept_root.join("t0/z").join(name), &run_dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("f"), b"x").unwrap();
            used(&bs, name, &dir, 0);
            mounted.push(dir);
        }
        assert_eq!(mounted, [run_dir.join("cache/cache"), kept_root.join("t0/z/data")]);
        std::fs::create_dir_all(run_dir.join("workspace")).unwrap();
        // Running: nothing goes, however old.
        assert!(sweep(&kept_root, &runs, &|_| true, &mounted, 10 * 3_600_000).is_empty());
        box_ended(&bs, &kept_root, &run_dir, 1000);
        // Within both retentions: nothing.
        assert!(sweep(&kept_root, &runs, &|_| false, &[], 1000 + 3_599_000).is_empty());
        // Past the cache's: the cache goes, the workspace stays.
        let swept = sweep(&kept_root, &runs, &|_| false, &[], 1000 + 3_601_000);
        assert_eq!(swept.iter().map(|s| s.0.clone()).collect::<Vec<_>>(), [run_dir.join("cache")]);
        assert!(run_dir.join("workspace").is_dir() && !run_dir.join("cache").exists());
        // The kept volume, while some box has it mounted, stays; once not, past its retention, goes.
        assert!(sweep(&kept_root, &runs, &|_| false, &[kept_root.join("t0/z/data")], 1000 + 7_201_000).is_empty());
        let swept = sweep(&kept_root, &runs, &|_| false, &[], 1000 + 7_201_000);
        assert_eq!(swept.iter().map(|s| s.0.clone()).collect::<Vec<_>>(), [kept_root.join("t0/z/data")]);
        assert!(!kept_root.join("t0/z/.data.life.json").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// From a control host before #377 there is no lifecycle: every volume is the zone's, kept
    /// forever, as before.
    #[test]
    fn a_start_without_lifecycles_keeps_every_volume() {
        let d = tmp("old");
        let (kept_root, runs) = (d.join("volumes"), d.join("runs"));
        let bs = start(None);
        for (name, _) in &bs.volumes {
            let dir = dir_for(&bs, name, kept_root.join("t0/z").join(name), &runs.join("run_a"));
            assert!(dir.starts_with(&kept_root));
            std::fs::create_dir_all(&dir).unwrap();
            used(&bs, name, &dir, 0);
        }
        box_ended(&bs, &kept_root, &runs.join("run_a"), 0);
        assert!(sweep(&kept_root, &runs, &|_| false, &[], i64::MAX / 2).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_collected_runs_caches_are_dropped() {
        let d = tmp("drop");
        std::fs::create_dir_all(d.join("cache/x")).unwrap();
        assert!(drop_caches(&d));
        assert!(!drop_caches(&d));
    }
}
