//! Garbage collection of the images a node was given (#191): an image that reached this node over
//! the control channel or from a registry, and that no box has started from for
//! [`keep_days`] days (7 by default; `node.json`'s `image_keep_days`, 0 to keep them all), is
//! removed from its runtime. Only those images: one the node didn't import itself is never
//! touched, and a node that shares the control host's runtime (`shares_host`) collects nothing.
//!
//! Removal is never forced, so the runtime keeps an image any container (running or not) was made
//! from. Nor is an image a live box may still start from removed: its own, and every pinned entry
//! of its zone's `images`, which it may start children from on this node itself (#164). A removed image a later box needs is sent or pulled again, as for a node that never had
//! it. Each removal is audited as `image.removed`.
//!
//! What it knows is `<node dir>/image-uses.json`: each imported digest, and when it was last
//! imported or started from (Unix ms).

use super::*;
use std::collections::BTreeMap;

/// How often the node looks for images to remove.
pub(super) const SWEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(3600);
/// How long an unused image is kept, by default.
const KEEP_DAYS: u64 = 7;

/// One serialises the record's reads and writes.
static RECORD: Mutex<()> = Mutex::new(());

fn record_path(root: &std::path::Path) -> PathBuf {
    root.join("image-uses.json")
}

/// The imported digests, and when each was last used (Unix ms).
pub(super) type Uses = BTreeMap<String, i64>;

fn read(root: &std::path::Path) -> Uses {
    std::fs::read(record_path(root)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn write(root: &std::path::Path, u: &Uses) -> Result<()> {
    let p = record_path(root);
    let tmp = p.with_extension("json.part");
    std::fs::write(&tmp, serde_json::to_vec(u)?)?;
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

/// Digest `digest` was imported here at `now`: it is the node's to collect.
pub(super) fn imported(root: &std::path::Path, digest: &str, now: i64) {
    let _one = RECORD.lock().expect("image uses");
    let mut u = read(root);
    u.insert(digest.to_string(), now);
    if let Err(e) = write(root, &u) {
        say_err!("[node] recording image {digest}: {e:#}");
    }
}

/// A box started from `digest` at `now`: kept for another [`keep_days`], if the node imported it.
pub(super) fn used(root: &std::path::Path, digest: &str, now: i64) {
    let _one = RECORD.lock().expect("image uses");
    let mut u = read(root);
    if let Some(at) = u.get_mut(digest) {
        *at = now;
        if let Err(e) = write(root, &u) {
            say_err!("[node] recording image {digest}: {e:#}");
        }
    }
}

/// How many days an unused image is kept: `node.json`'s `image_keep_days`, else 7. None: forever
/// (0, or a node sharing the control host's runtime).
pub(super) fn keep_days(paths: &NodePaths) -> Option<u64> {
    if paths.shared.is_some() {
        return None;
    }
    let info = std::fs::read(paths.root.join("node.json")).ok().and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok());
    match info.as_ref().map(|v| &v["image_keep_days"]) {
        Some(serde_json::Value::Number(n)) => n.as_u64().filter(|d| *d > 0),
        _ => Some(KEEP_DAYS),
    }
}

/// The digests unused since before `now - keep_days`.
pub(super) fn due(u: &Uses, now: i64, keep_days: u64) -> Vec<String> {
    let before = now.saturating_sub((keep_days as i64).saturating_mul(86_400_000));
    u.iter().filter(|(_, at)| **at < before).map(|(d, _)| d.clone()).collect()
}

/// The digests a live box here may start from: its own, and the pins of its zone's `images`.
fn in_reach(node: &Node) -> std::collections::BTreeSet<String> {
    let starts: Vec<(Option<String>, Option<String>, Option<String>)> = node
        .boxes
        .lock()
        .expect("boxes")
        .values()
        .map(|b| {
            (
                b.record.start.image_pin.clone(),
                b.record.image_digest.clone(),
                b.record.start.edge.as_ref().and_then(|e| e.spawn.as_ref()).map(|s| s.manifest.clone()),
            )
        })
        .collect();
    let mut keep = std::collections::BTreeSet::new();
    for (pin, digest, manifest) in starts {
        keep.extend(pin);
        keep.extend(digest);
        if let Some(m) = manifest.and_then(|m| wicket_agent::load(&m).ok()) {
            keep.extend(m.zone.images.iter().filter_map(|i| wicket_core::image::parse(i).ok().and_then(|r| r.pin)));
        }
    }
    keep
}

/// Removes the images due, as [`due`] picks them; returns what it removed.
pub(super) async fn sweep(node: &Arc<Node>) -> Vec<String> {
    let Some(days) = keep_days(&node.paths) else { return vec![] };
    let now = (node.clock)();
    let reach = in_reach(node);
    let todo: Vec<String> = {
        let _one = RECORD.lock().expect("image uses");
        due(&read(&node.paths.root), now, days)
    };
    let (todo, kept): (Vec<String>, Vec<String>) = todo.into_iter().partition(|d| !reach.contains(d));
    if !kept.is_empty() {
        // A live box may start from them: used now.
        let _one = RECORD.lock().expect("image uses");
        let mut u = read(&node.paths.root);
        for d in &kept {
            u.insert(d.clone(), now);
        }
        let _ = write(&node.paths.root, &u);
    }
    let mut removed = vec![];
    for digest in todo {
        let last = read(&node.paths.root).get(&digest).copied();
        let r = node.docker.remove_image(&digest).await;
        let _one = RECORD.lock().expect("image uses");
        let mut u = read(&node.paths.root);
        // Started from since it was picked: kept.
        if u.get(&digest).copied() != last {
            continue;
        }
        match r {
            Ok(wicket_sandbox::ImageRemoval::Removed) | Ok(wicket_sandbox::ImageRemoval::Absent) => {
                let was = matches!(r, Ok(wicket_sandbox::ImageRemoval::Removed));
                u.remove(&digest);
                if let Err(e) = write(&node.paths.root, &u) {
                    say_err!("[node] recording image {digest}: {e:#}");
                }
                if was {
                    say_err!("[node] image {digest} removed: unused for {days} days");
                    let body = serde_json::json!({ "digest": digest, "last_used": last, "keep_days": days });
                    let _ = node.audit.lock().expect("audit").audit(&wicket_core::TenantId::single(), None, "image.removed", &body);
                    removed.push(digest);
                }
            }
            Ok(wicket_sandbox::ImageRemoval::Kept(why)) => {
                // A container still uses it: counted as used now, so it isn't asked again hourly.
                u.insert(digest.clone(), now);
                let _ = write(&node.paths.root, &u);
                say_err!("[node] image {digest} kept: {why}");
            }
            Err(e) => say_err!("[node] removing image {digest}: {e:#}"),
        }
    }
    if !removed.is_empty() {
        node.ship_audit();
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400_000;

    #[test]
    fn only_what_went_unused_past_the_keep_is_due() {
        let u: Uses = [("sha256:old".to_string(), 0), ("sha256:recent".to_string(), 6 * DAY), ("sha256:edge".to_string(), 3 * DAY)]
            .into_iter()
            .collect();
        assert_eq!(due(&u, 10 * DAY, 7), vec!["sha256:old".to_string()]);
        assert_eq!(due(&u, 10 * DAY, 1), vec!["sha256:edge", "sha256:old", "sha256:recent"]);
        assert!(due(&u, 0, 7).is_empty());
    }

    #[test]
    fn only_imported_images_are_recorded_and_a_start_keeps_them() {
        let d = std::env::temp_dir().join(format!("wicket-imagegc-{}-{}", std::process::id(), wicket_core::new_ulid()));
        std::fs::create_dir_all(&d).unwrap();
        used(&d, "sha256:built-here", 5);
        assert!(read(&d).is_empty(), "a start never adds an image the node didn't import");
        imported(&d, "sha256:a", 1);
        used(&d, "sha256:a", 9);
        assert_eq!(read(&d).get("sha256:a"), Some(&9));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_keep_comes_from_node_json_and_a_shared_node_keeps_everything() {
        let d = std::env::temp_dir().join(format!("wicket-imagegc-keep-{}-{}", std::process::id(), wicket_core::new_ulid()));
        std::fs::create_dir_all(&d).unwrap();
        assert_eq!(keep_days(&NodePaths::new(Some(d.clone()))), Some(7));
        std::fs::write(d.join("node.json"), br#"{"image_keep_days": 2}"#).unwrap();
        assert_eq!(keep_days(&NodePaths::new(Some(d.clone()))), Some(2));
        std::fs::write(d.join("node.json"), br#"{"image_keep_days": 0}"#).unwrap();
        assert_eq!(keep_days(&NodePaths::new(Some(d.clone()))), None);
        std::fs::write(d.join("node.json"), br#"{"shares_host": true, "data_dir": "/x"}"#).unwrap();
        assert_eq!(keep_days(&NodePaths::new(Some(d.clone()))), None, "the control host's own node");
        std::fs::remove_dir_all(&d).unwrap();
    }
}
