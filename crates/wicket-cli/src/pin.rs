//! `wicket zone pin MANIFEST` (#192): rewrites a manifest's image tags (`zone.images`, `agent.image`,
//! `program.image`) to the digests they point to now, in place, keeping the rest of the file as it
//! is (comments, layout). The digests are what this installation's Docker reports (`wicket image
//! digest`, through wicketd on an installed host). The rewrite is checked by reading the manifest
//! back: it must be the same manifest with exactly those images pinned, or nothing is written.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::Path;

/// The tags `m` names, unpinned.
pub fn tags(m: &wicket_core::Manifest) -> Vec<String> {
    let mut v: Vec<String> = m.zone.images.clone();
    v.extend(m.agent.as_ref().and_then(|a| a.image.clone()));
    v.extend(m.program.as_ref().and_then(|p| p.image.clone()));
    v.retain(|i| !i.trim().is_empty() && !wicket_core::image::is_pinned(i));
    v.sort();
    v.dedup();
    v
}

/// `text` with every occurrence of each tag in `pins` (as a whole YAML scalar) replaced by its pin.
pub fn rewrite(text: &str, pins: &BTreeMap<String, String>) -> String {
    let before = |c: Option<char>| c.is_none_or(|c| c.is_whitespace() || "[,'\"".contains(c));
    let after = |c: Option<char>| c.is_none_or(|c| c.is_whitespace() || "],'\"#".contains(c));
    let mut out = text.to_string();
    for (tag, pin) in pins {
        let mut s = String::new();
        let mut rest = out.as_str();
        while let Some(i) = rest.find(tag.as_str()) {
            let (head, tail) = rest.split_at(i);
            let ok = before(head.chars().last().or_else(|| s.chars().last())) && after(tail[tag.len()..].chars().next());
            s.push_str(head);
            s.push_str(if ok { pin } else { tag });
            rest = &tail[tag.len()..];
        }
        s.push_str(rest);
        out = s;
    }
    out
}

/// What `m` is with each tag in `pins` pinned.
fn expected(m: &wicket_core::Manifest, pins: &BTreeMap<String, String>) -> wicket_core::Manifest {
    let pin = |i: &mut String| {
        if let Some(p) = pins.get(i.as_str()) {
            *i = p.clone();
        }
    };
    let mut e = m.clone();
    e.zone.images.iter_mut().for_each(pin);
    if let Some(i) = e.agent.as_mut().and_then(|a| a.image.as_mut()) {
        pin(i);
    }
    if let Some(i) = e.program.as_mut().and_then(|p| p.image.as_mut()) {
        pin(i);
    }
    e
}

/// The digest each of `refs` points to here, asked of `wicket image digest`.
fn digests(refs: &[String]) -> Result<BTreeMap<String, String>> {
    let exe = crate::update::self_exe()?;
    let out = std::process::Command::new(exe).args(["image", "digest"]).args(refs).output().context("wicket image digest")?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let mut m = BTreeMap::new();
    for l in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some((r, d)) = l.split_once(' ') {
            m.insert(r.to_string(), d.trim().to_string());
        }
    }
    Ok(m)
}

pub fn pin(manifest: &Path, dry_run: bool) -> Result<()> {
    let text = std::fs::read_to_string(manifest).with_context(|| manifest.display().to_string())?;
    let m = wicket_core::Manifest::from_yaml(&text)?;
    let tags = tags(&m);
    if tags.is_empty() {
        println!("{}: every image is pinned already", manifest.display());
        return Ok(());
    }
    let found = digests(&tags)?;
    let mut pins = BTreeMap::new();
    for t in &tags {
        let d = found.get(t).with_context(|| format!("no digest for {t}"))?;
        pins.insert(t.clone(), wicket_core::image::pinned(t, d));
    }
    let new = rewrite(&text, &pins);
    let back = wicket_core::Manifest::from_yaml(&new).context("the rewritten manifest")?;
    if serde_json::to_value(&back)? != serde_json::to_value(expected(&m, &pins))? {
        bail!("{}: couldn't pin it safely (a tag appears elsewhere in the file as well); pin it by hand", manifest.display());
    }
    for (t, p) in &pins {
        println!("{t} -> {p}");
    }
    if dry_run {
        return Ok(());
    }
    let tmp = manifest.with_extension("pinning");
    std::fs::write(&tmp, &new)?;
    std::fs::rename(&tmp, manifest)?;
    println!("pinned {} image(s) in {}", pins.len(), manifest.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_are_rewritten_where_they_are_images_and_nowhere_else() {
        let d = format!("sha256:{}", "c".repeat(64));
        let text = "# images: img:dev is ours\ntask: build img:dev's docs\nagent:\n  name: a\n  image: \"img:dev\"\nzone:\n  name: z\n  llm: { secret: m }\n  images: [img:dev, 'other:1']\n";
        let m = wicket_core::Manifest::from_yaml(text).unwrap();
        assert_eq!(tags(&m), vec!["img:dev".to_string(), "other:1".to_string()]);
        let pins: BTreeMap<String, String> = [
            ("img:dev".to_string(), wicket_core::image::pinned("img:dev", &d)),
            ("other:1".to_string(), wicket_core::image::pinned("other:1", &d)),
        ]
        .into();
        let new = rewrite(text, &pins);
        let back = wicket_core::Manifest::from_yaml(&new).unwrap();
        // The task text mentions the tag too: rewritten as well, so the check refuses it.
        assert_ne!(serde_json::to_value(&back).unwrap(), serde_json::to_value(expected(&m, &pins)).unwrap());
        // Without it, the rewrite is exact, and the comment is kept.
        let text2 = text.replace("task: build img:dev's docs", "task: build the docs");
        let m2 = wicket_core::Manifest::from_yaml(&text2).unwrap();
        let new2 = rewrite(&text2, &pins);
        assert_eq!(
            serde_json::to_value(wicket_core::Manifest::from_yaml(&new2).unwrap()).unwrap(),
            serde_json::to_value(expected(&m2, &pins)).unwrap()
        );
        assert!(new2.contains(&format!("image: \"img@{d}\"")) && new2.contains(&format!("'other@{d}'")));
        assert!(new2.contains("# images: img:dev is ours") || new2.contains(&format!("# images: img@{d} is ours")));
        // A longer tag that starts with a shorter one isn't touched by it.
        let p: BTreeMap<String, String> = [("img:dev".to_string(), "X".to_string())].into();
        assert_eq!(rewrite("images: [img:dev2, img:dev]", &p), "images: [img:dev2, X]");
    }
}
