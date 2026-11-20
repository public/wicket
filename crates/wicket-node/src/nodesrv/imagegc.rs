//! Garbage collection of the images a node was given (#191): an image that reached this node over
//! the control channel or from a registry, and that no box has used for [`keep_days`] days of the
//! node serving (7 by default; `node.json`'s `image_keep_days`, 0 to keep them all), is removed
//! from its runtime. Only those images: one the node didn't import itself is never touched, and a
//! node that shares the control host's runtime (`shares_host`) collects nothing.
//!
//! - **Used** means imported, started from, or reported present to the control host
//!   (`ImageHave`, which it asks before placing a box with it).
//! - **Never forced**: the runtime keeps an image any container (running or not) was made from.
//! - **Not while it may be started from**: a box start [`hold`]s its image from resolving it until
//!   the box is live, and a live box keeps its own image and every pinned entry of its zone's
//!   `images`, which it may start children from on this node itself (#164). The sweep checks all
//!   of that again, under the lock starts take, just before it removes an image; a start that
//!   comes while one is being removed waits for it.
//! - **Serving time**: time the node wasn't serving doesn't count, so a node back after a week
//!   away doesn't remove everything at once.
//! - **Recorded**: `image.removed`, `image.kept` (the runtime's reason) and `image.remove_failed`
//!   in the node's audit.
//!
//! A removed image a later box needs is sent or pulled again, as for a node that never had it; if
//! neither the control host nor a registry has it, the start fails saying so. What the node knows
//! is `<node dir>/image-uses.json`.

use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// How often the node looks for images to remove.
pub(super) const SWEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(3600);
/// How long an unused image is kept, by default.
const KEEP_DAYS: u64 = 7;
/// A keep longer than this (100 years) is forever.
const KEEP_DAYS_MAX: u64 = 36_500;
const DAY_MS: i64 = 86_400_000;

/// What the node knows of the images it was given.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(super) struct Record {
    /// Each imported digest, and when it was last used (Unix ms, shifted by any time not serving).
    #[serde(default)]
    pub(super) uses: BTreeMap<String, i64>,
    /// When the last sweep ran (Unix ms).
    #[serde(default)]
    pub(super) seen: Option<i64>,
}

/// Starts in progress and removals in progress.
#[derive(Default)]
struct State {
    held: BTreeMap<String, usize>,
    removing: BTreeSet<String>,
}

/// One serialises the record's reads and writes; taken before [`STATE`] where both are.
static RECORD: Mutex<()> = Mutex::new(());
static STATE: Mutex<State> = Mutex::new(State { held: BTreeMap::new(), removing: BTreeSet::new() });

fn record_path(root: &std::path::Path) -> PathBuf {
    root.join("image-uses.json")
}

pub(super) fn read(root: &std::path::Path) -> Record {
    std::fs::read(record_path(root)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn write(root: &std::path::Path, r: &Record) {
    let p = record_path(root);
    let tmp = p.with_extension("json.part");
    let done = serde_json::to_vec(r)
        .map_err(anyhow::Error::from)
        .and_then(|b| Ok(std::fs::write(&tmp, b)?))
        .and_then(|_| Ok(std::fs::rename(&tmp, &p)?));
    if let Err(e) = done {
        say_err!("[node] recording the images it was given: {e:#}");
    }
}

/// Digest `digest` was imported here at `now`: it is the node's to collect.
pub(super) fn imported(root: &std::path::Path, digest: &str, now: i64) {
    let _one = RECORD.lock().expect("image uses");
    let mut r = read(root);
    r.uses.insert(digest.to_string(), now);
    write(root, &r);
}

/// `digest` was used at `now` (started from, or reported present): kept for another
/// [`keep_days`], if the node imported it.
pub(super) fn used(root: &std::path::Path, digest: &str, now: i64) {
    let _one = RECORD.lock().expect("image uses");
    let mut r = read(root);
    if let Some(at) = r.uses.get_mut(digest) {
        *at = (*at).max(now);
        write(root, &r);
    }
}

/// A start's hold on its image: no sweep removes it while this lives.
pub(super) struct Hold(String);

impl Drop for Hold {
    fn drop(&mut self) {
        let mut s = STATE.lock().expect("image gc");
        if let Some(n) = s.held.get_mut(&self.0) {
            *n -= 1;
            if *n == 0 {
                s.held.remove(&self.0);
            }
        }
    }
}

/// Holds `digest` for a box starting from it (until it is live), and counts it used at `now`. If a
/// sweep is removing it, waits until it has: the start then finds it gone, or still there.
pub(super) async fn hold(root: &std::path::Path, digest: &str, now: i64) -> Hold {
    loop {
        {
            let mut s = STATE.lock().expect("image gc");
            if !s.removing.contains(digest) {
                *s.held.entry(digest.to_string()).or_default() += 1;
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    used(root, digest, now);
    Hold(digest.to_string())
}

/// How many days an unused image is kept: `node.json`'s `image_keep_days`, else 7. None: forever
/// (0, more than 100 years, a node sharing the control host's runtime, or a value that isn't a
/// whole number of days, which is said).
pub(super) fn keep_days(paths: &NodePaths) -> Option<u64> {
    if paths.shared.is_some() {
        return None;
    }
    let info = std::fs::read(paths.root.join("node.json")).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    let v = info.as_ref().map(|v| &v["image_keep_days"]).unwrap_or(&serde_json::Value::Null);
    match v {
        serde_json::Value::Null => Some(KEEP_DAYS),
        serde_json::Value::Number(n) => match n.as_u64() {
            Some(0) => None,
            Some(d) if d > KEEP_DAYS_MAX => None,
            Some(d) => Some(d),
            None => {
                say_err!("[node] node.json's image_keep_days {n} is not a whole number of days: keeping every image");
                None
            }
        },
        other => {
            say_err!("[node] node.json's image_keep_days {other} is not a number of days: keeping every image");
            None
        }
    }
}

/// The digests unused since before `now - keep_days`.
pub(super) fn due(r: &Record, now: i64, keep_days: u64) -> Vec<String> {
    let before = now.saturating_sub((keep_days.min(KEEP_DAYS_MAX) as i64).saturating_mul(DAY_MS));
    r.uses.iter().filter(|(_, at)| **at < before).map(|(d, _)| d.clone()).collect()
}

/// Credits the time the node wasn't serving since the last sweep (beyond one sweep's interval) to
/// every image, so it doesn't count against them, and marks this sweep.
pub(super) fn credit(r: &mut Record, now: i64) {
    let every = SWEEP_EVERY.as_millis() as i64;
    if let Some(seen) = r.seen {
        let away = now.saturating_sub(seen).saturating_sub(every);
        if away > every {
            for at in r.uses.values_mut() {
                *at = at.saturating_add(away).min(now);
            }
        }
    }
    r.seen = Some(now);
}

/// The digests a live box here may start from: its own, and the pins of its zone's `images`.
/// `starts` is each box's pin, its image's digest, and its manifest (YAML), if it has them.
pub(super) fn reach_of(starts: &[(Option<String>, Option<String>, Option<String>)]) -> BTreeSet<String> {
    let mut keep = BTreeSet::new();
    for (pin, digest, manifest) in starts {
        keep.extend(pin.clone());
        keep.extend(digest.clone());
        if let Some(m) = manifest.as_deref().and_then(|m| wicket_agent::load(m).ok()) {
            keep.extend(m.zone.images.iter().filter_map(|i| wicket_core::image::parse(i).ok().and_then(|r| r.pin)));
        }
    }
    keep
}

fn in_reach(node: &Node) -> BTreeSet<String> {
    let starts: Vec<_> = node
        .boxes
        .lock()
        .expect("boxes")
        .values()
        .map(|b| {
            let manifest = b.record.start.edge.as_ref().and_then(|e| e.spawn.as_ref()).map(|s| s.manifest.clone());
            (b.record.start.image_pin.clone(), b.record.image_digest.clone(), manifest)
        })
        .collect();
    reach_of(&starts)
}

fn audit(node: &Node, kind: &str, body: serde_json::Value) {
    if let Err(e) = node.audit.lock().expect("audit").audit(&wicket_core::TenantId::single(), None, kind, &body) {
        say_err!("[node] auditing {kind}: {e:#}");
    }
}

/// Removes the images due, as [`due`] picks them, unless a start holds one or a live box may start
/// from it; returns what it removed.
pub(super) async fn sweep(node: &Arc<Node>) -> Vec<String> {
    let Some(days) = keep_days(&node.paths) else { return vec![] };
    let root = node.paths.root.clone();
    let now = (node.clock)();
    let todo = {
        let _one = RECORD.lock().expect("image uses");
        let mut r = read(&root);
        credit(&mut r, now);
        write(&root, &r);
        due(&r, now, days)
    };
    let mut removed = vec![];
    for digest in todo {
        // Checked again, as starts see it, just before it is removed.
        let last = {
            let _one = RECORD.lock().expect("image uses");
            let r = read(&root);
            let mut s = STATE.lock().expect("image gc");
            let still_due = due(&r, now, days).contains(&digest);
            let held = s.held.contains_key(&digest);
            if !still_due || held {
                continue;
            }
            if in_reach(node).contains(&digest) {
                drop(s);
                // A live box may start from it: used now.
                let mut r = r;
                r.uses.insert(digest.clone(), now);
                write(&root, &r);
                continue;
            }
            s.removing.insert(digest.clone());
            r.uses.get(&digest).copied()
        };
        let result = node.docker.remove_image(&digest).await;
        // What the node knows of its images is forgotten before a waiting start goes on, so the
        // start asks the runtime afresh rather than trusting the cache until Docker's delete event
        // arrives (#287): it then finds the image gone, and says so.
        if matches!(result, Ok(wicket_sandbox::ImageRemoval::Removed)) {
            node.idents.invalidate();
        }
        let _one = RECORD.lock().expect("image uses");
        STATE.lock().expect("image gc").removing.remove(&digest);
        let mut r = read(&root);
        match result {
            Ok(wicket_sandbox::ImageRemoval::Removed) => {
                r.uses.remove(&digest);
                write(&root, &r);
                say_err!("[node] image {digest} removed: unused for {days} days");
                audit(node, "image.removed", serde_json::json!({ "digest": digest, "last_used": last, "keep_days": days }));
                removed.push(digest);
            }
            Ok(wicket_sandbox::ImageRemoval::Absent) => {
                r.uses.remove(&digest);
                write(&root, &r);
            }
            Ok(wicket_sandbox::ImageRemoval::Kept(why)) => {
                // A container still uses it: counted as used now, so it isn't asked about hourly.
                r.uses.insert(digest.clone(), now);
                write(&root, &r);
                say_err!("[node] image {digest} kept: {why}");
                audit(node, "image.kept", serde_json::json!({ "digest": digest, "why": why }));
            }
            Err(e) => {
                // Left as it was: tried again at the next sweep.
                say_err!("[node] removing image {digest}: {e:#}");
                audit(node, "image.remove_failed", serde_json::json!({ "digest": digest, "why": format!("{e:#}") }));
            }
        }
    }
    node.ship_audit();
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = DAY_MS;

    fn rec(uses: &[(&str, i64)]) -> Record {
        Record { uses: uses.iter().map(|(d, a)| (d.to_string(), *a)).collect(), seen: None }
    }

    #[test]
    fn only_what_went_unused_past_the_keep_is_due() {
        let r = rec(&[("sha256:old", 0), ("sha256:recent", 6 * DAY), ("sha256:edge", 3 * DAY)]);
        assert_eq!(due(&r, 10 * DAY, 7), vec!["sha256:old".to_string()]);
        assert_eq!(due(&r, 10 * DAY, 1), vec!["sha256:edge", "sha256:old", "sha256:recent"]);
        assert!(due(&r, 0, 7).is_empty());
        assert!(due(&r, 10 * DAY, u64::MAX).is_empty(), "a huge keep doesn't wrap into removing everything");
    }

    #[test]
    fn time_not_serving_doesnt_count() {
        let hour = SWEEP_EVERY.as_millis() as i64;
        // Swept an hour ago: nothing credited.
        let mut r = rec(&[("sha256:a", 0)]);
        r.seen = Some(10 * DAY - hour);
        credit(&mut r, 10 * DAY);
        assert_eq!((r.uses["sha256:a"], r.seen), (0, Some(10 * DAY)));
        // Last swept 8 days ago, last used then: back now, it has been unused for an hour of serving.
        let mut r = rec(&[("sha256:a", 2 * DAY)]);
        r.seen = Some(2 * DAY);
        credit(&mut r, 10 * DAY);
        assert_eq!(r.uses["sha256:a"], 10 * DAY - hour);
        assert!(due(&r, 10 * DAY, 7).is_empty(), "not removed on its return");
    }

    #[test]
    fn only_imported_images_are_recorded_and_a_use_keeps_them() {
        let d = std::env::temp_dir().join(format!("wicket-imagegc-{}-{}", std::process::id(), wicket_core::new_ulid()));
        std::fs::create_dir_all(&d).unwrap();
        used(&d, "sha256:built-here", 5);
        assert!(read(&d).uses.is_empty(), "a use never adds an image the node didn't import");
        imported(&d, "sha256:a", 1);
        used(&d, "sha256:a", 9);
        used(&d, "sha256:a", 3);
        assert_eq!(read(&d).uses.get("sha256:a"), Some(&9), "never earlier");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_keep_comes_from_node_json_and_odd_values_keep_everything() {
        let d = std::env::temp_dir().join(format!("wicket-imagegc-keep-{}-{}", std::process::id(), wicket_core::new_ulid()));
        std::fs::create_dir_all(&d).unwrap();
        let keep = |j: &str| {
            std::fs::write(d.join("node.json"), j).unwrap();
            keep_days(&NodePaths::new(Some(d.clone())))
        };
        assert_eq!(keep("{}"), Some(7));
        assert_eq!(keep(r#"{"image_keep_days": 2}"#), Some(2));
        assert_eq!(keep(r#"{"image_keep_days": 0}"#), None);
        assert_eq!(keep(r#"{"image_keep_days": 18446744073709551615}"#), None, "forever, not a wrap");
        assert_eq!(keep(r#"{"image_keep_days": "0"}"#), None, "not a number: refused, everything kept");
        assert_eq!(keep(r#"{"image_keep_days": 1.5}"#), None);
        assert_eq!(keep(r#"{"image_keep_days": -1}"#), None);
        assert_eq!(keep(r#"{"shares_host": true, "data_dir": "/x"}"#), None, "the control host's own node");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_live_box_keeps_its_image_and_its_zone_s_pinned_images() {
        let (a, b, c) = (format!("sha256:{}", "a".repeat(64)), format!("sha256:{}", "b".repeat(64)), format!("sha256:{}", "c".repeat(64)));
        let m = format!("task: t\nagent: {{name: a}}\nzone: {{name: z, llm: {{secret: m}}, images: ['x/child@{b}', 'y/tagged:1']}}");
        let reach = reach_of(&[(Some(a.clone()), None, Some(m)), (None, Some(c.clone()), None)]);
        assert_eq!(reach, [a, b, c].into_iter().collect::<BTreeSet<_>>(), "its own, its zone's pinned ones, another box's digest");
        assert!(reach_of(&[(None, None, Some("not a manifest".into()))]).is_empty());
    }

    #[tokio::test]
    async fn a_start_waits_for_a_removal_under_way() {
        let d = std::env::temp_dir().join(format!("wicket-imagegc-hold-{}-{}", std::process::id(), wicket_core::new_ulid()));
        std::fs::create_dir_all(&d).unwrap();
        let digest = format!("sha256:{}", wicket_core::new_ulid());
        STATE.lock().unwrap().removing.insert(digest.clone());
        let (dd, dg) = (d.clone(), digest.clone());
        let start = tokio::spawn(async move { hold(&dd, &dg, 1).await });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!start.is_finished(), "held back while it is being removed");
        STATE.lock().unwrap().removing.remove(&digest);
        let h = start.await.unwrap();
        assert_eq!(STATE.lock().unwrap().held.get(&digest), Some(&1));
        drop(h);
        assert!(!STATE.lock().unwrap().held.contains_key(&digest));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
