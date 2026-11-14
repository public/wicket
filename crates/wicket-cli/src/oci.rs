//! OCI image layouts (#191): an image delivered to a node as an archive, verified before it is
//! imported.
//!
//! The archive is an [OCI image layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md)
//! as a tar stream (`oci-layout`, `index.json`, `blobs/sha256/<hex>`), as `docker save` writes it.
//! [`unpack_verified`] reads it as it arrives and keeps nothing it hasn't checked:
//!
//! - only those names, as regular files (no links, devices or other paths), each once; a legacy
//!   `manifest.json` (tags) and the sender's `index.json` are read past and dropped, so the sender
//!   names nothing;
//! - every blob hashes to its own name, as it is written;
//! - the pin (`sha256:…`) is a blob of the archive, and an image index or manifest: from it, every
//!   manifest's config and layers are there, with the sizes their descriptors give, and at least
//!   one manifest is complete. An index may name manifests the archive lacks (other platforms, as
//!   a Docker saves an image pulled for one); they are left out;
//! - blobs the pin doesn't reach are deleted.
//!
//! It then writes its own `oci-layout` and `index.json`, naming the pin alone, so what a runtime
//! imports is exactly what was checked. Nothing here is specific to a runtime: the runtime adapter
//! imports the directory (Docker's `load`, or a backend's conversion to a root filesystem, #64).

use anyhow::{bail, Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::path::Path;

/// The most `index.json`, `oci-layout`, `manifest.json` or a manifest or index blob may be.
const SMALL_MAX: u64 = 4 << 20;
/// How deep indexes may nest.
const DEPTH_MAX: usize = 4;

const INDEX_TYPES: [&str; 2] = ["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"];
const MANIFEST_TYPES: [&str; 2] = ["application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"];

/// What [`unpack_verified`] kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unpacked {
    /// The pin's media type (an index or a manifest).
    pub media_type: String,
    /// The bytes of the blobs kept.
    pub bytes: u64,
    /// The image manifests kept whole.
    pub manifests: usize,
}

fn hex_of(digest: &str) -> Option<&str> {
    digest.strip_prefix("sha256:").filter(|h| h.len() == 64 && h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
}

/// Reads the layout archive `r` into `dir` (an empty directory), checks it holds the image `pin`
/// whole, and leaves there a layout of that image alone, named `name` (`repository@pin`) if given.
/// `max` caps the bytes taken from the archive's blobs.
pub fn unpack_verified(r: impl Read, dir: &Path, pin: &str, name: Option<&str>, max: u64) -> Result<Unpacked> {
    if hex_of(pin).is_none() {
        bail!("{pin:?} is not a sha256 digest");
    }
    let blobs = dir.join("blobs/sha256");
    std::fs::create_dir_all(&blobs)?;
    let mut have: HashMap<String, u64> = HashMap::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut total = 0u64;
    let mut ar = tar::Archive::new(r);
    for e in ar.entries().context("reading the image archive")? {
        let mut e = e.context("reading the image archive")?;
        let path = e.path().context("an entry's name")?.to_string_lossy().into_owned();
        let path = path.strip_prefix("./").unwrap_or(&path).to_string();
        let kind = e.header().entry_type();
        if kind.is_dir() {
            if !matches!(path.trim_end_matches('/'), "blobs" | "blobs/sha256" | "" | ".") {
                bail!("the image archive has an unexpected directory {path:?}");
            }
            continue;
        }
        if !kind.is_file() {
            bail!("the image archive's {path:?} is not a regular file");
        }
        if !seen.insert(path.clone()) {
            bail!("the image archive has {path:?} twice");
        }
        match path.as_str() {
            // Read past: this layout's own are written below.
            "oci-layout" | "index.json" | "manifest.json" => {
                if e.size() > SMALL_MAX {
                    bail!("the image archive's {path} is too large");
                }
                std::io::copy(&mut e, &mut std::io::sink())?;
            }
            p => {
                let Some(hex) = p.strip_prefix("blobs/sha256/").filter(|h| hex_of(&format!("sha256:{h}")).is_some()) else {
                    bail!("the image archive has an unexpected entry {p:?}");
                };
                total = total.saturating_add(e.size());
                if total > max {
                    bail!("the image archive is larger than {max} bytes");
                }
                let part = blobs.join(format!("{hex}.part"));
                let mut f = std::fs::File::create(&part)?;
                let mut h = Sha256::new();
                let mut buf = vec![0u8; 256 * 1024];
                let mut n = 0u64;
                loop {
                    let k = e.read(&mut buf).context("reading the image archive")?;
                    if k == 0 {
                        break;
                    }
                    h.update(&buf[..k]);
                    f.write_all(&buf[..k])?;
                    n += k as u64;
                }
                if hex::encode(h.finalize()) != hex {
                    let _ = std::fs::remove_file(&part);
                    bail!("blob sha256:{hex} in the image archive does not match its digest");
                }
                std::fs::rename(&part, blobs.join(hex))?;
                have.insert(format!("sha256:{hex}"), n);
            }
        }
    }
    let Some(&pin_size) = have.get(pin) else { bail!("the image archive does not hold {pin}") };
    let mut keep: HashSet<String> = HashSet::new();
    let mut manifests = 0;
    let media_type = walk(&blobs, &have, pin, pin_size, None, 0, &mut keep, &mut manifests)?;
    if manifests == 0 {
        bail!("the image archive holds no complete image under {pin}");
    }
    let mut bytes = 0;
    for (d, n) in &have {
        if keep.contains(d) {
            bytes += n;
        } else {
            std::fs::remove_file(blobs.join(hex_of(d).expect("checked")))?;
        }
    }
    let mut desc = serde_json::json!({ "mediaType": media_type, "digest": pin, "size": pin_size });
    if let Some(n) = name {
        desc["annotations"] = serde_json::json!({ "io.containerd.image.name": n });
    }
    let index = serde_json::json!({ "schemaVersion": 2, "mediaType": INDEX_TYPES[0], "manifests": [desc] });
    std::fs::write(dir.join("oci-layout"), br#"{"imageLayoutVersion":"1.0.0"}"#)?;
    std::fs::write(dir.join("index.json"), serde_json::to_vec(&index)?)?;
    Ok(Unpacked { media_type, bytes, manifests })
}

/// Checks blob `digest` (an index or a manifest) and what it names, marking what to keep. Returns
/// its media type.
#[allow(clippy::too_many_arguments)]
fn walk(
    blobs: &Path,
    have: &HashMap<String, u64>,
    digest: &str,
    size: u64,
    declared: Option<&str>,
    depth: usize,
    keep: &mut HashSet<String>,
    manifests: &mut usize,
) -> Result<String> {
    if depth > DEPTH_MAX {
        bail!("the image's indexes nest more than {DEPTH_MAX} deep");
    }
    if size > SMALL_MAX {
        bail!("{digest} is too large for an image index or manifest");
    }
    let v: Value = serde_json::from_slice(&std::fs::read(blobs.join(hex_of(digest).context("a digest")?))?)
        .with_context(|| format!("{digest} is not an image index or manifest"))?;
    let mt = v["mediaType"].as_str().or(declared).unwrap_or_default().to_string();
    let mt = match mt.as_str() {
        "" if v.get("manifests").is_some() => INDEX_TYPES[0].to_string(),
        "" if v.get("config").is_some() && v.get("layers").is_some() => MANIFEST_TYPES[0].to_string(),
        _ => mt,
    };
    keep.insert(digest.to_string());
    if INDEX_TYPES.contains(&mt.as_str()) {
        for d in v["manifests"].as_array().context("an index without manifests")? {
            let (cd, cs, ct) = descriptor(d)?;
            // An index may name what the archive lacks: another platform's image.
            if have.contains_key(&cd) {
                check_size(have, &cd, cs)?;
                walk(blobs, have, &cd, cs, ct.as_deref(), depth + 1, keep, manifests)?;
            }
        }
    } else if MANIFEST_TYPES.contains(&mt.as_str()) {
        let mut all = vec![descriptor(&v["config"]).context("the manifest's config")?];
        for l in v["layers"].as_array().context("a manifest without layers")? {
            all.push(descriptor(l)?);
        }
        for (d, s, _) in all {
            if !have.contains_key(&d) {
                bail!("the image archive lacks {d}, which manifest {digest} names");
            }
            check_size(have, &d, s)?;
            keep.insert(d);
        }
        *manifests += 1;
    } else if depth == 0 && v.get("rootfs").is_some() {
        bail!(
            "{digest} is an image config, not a manifest: the pin is a config digest, as a runtime that ids images by their config (Docker's classic image store) reports it; pin the manifest digest (Docker's containerd image store)"
        );
    } else {
        bail!("{digest} is neither an image index nor a manifest ({mt:?})");
    }
    Ok(mt)
}

fn descriptor(d: &Value) -> Result<(String, u64, Option<String>)> {
    let digest = d["digest"].as_str().filter(|x| hex_of(x).is_some()).context("a descriptor without a sha256 digest")?;
    let size = d["size"].as_u64().context("a descriptor without a size")?;
    Ok((digest.to_string(), size, d["mediaType"].as_str().map(String::from)))
}

fn check_size(have: &HashMap<String, u64>, d: &str, s: u64) -> Result<()> {
    match have.get(d) {
        Some(&n) if n == s => Ok(()),
        Some(&n) => bail!("{d} is {n} bytes; its descriptor says {s}"),
        None => bail!("the image archive lacks {d}"),
    }
}

/// The name a delivered image is imported under (`repository@pin`), so a node finds it by the
/// pinned reference as well as by its digest, and no tag moves. None for a bare digest.
pub fn import_name(image: &str, pin: &str) -> Option<String> {
    let r = wicket_core::image::parse(image).ok()?;
    if r.name.is_empty() {
        return None;
    }
    let repo = wicket_core::image::repository(&r.name);
    // Fully qualified, as a runtime's content store names it.
    let first = repo.split('/').next().unwrap_or_default();
    let qualified = match repo.contains('/') && (first.contains('.') || first.contains(':') || first == "localhost") {
        true => repo.to_string(),
        false if repo.contains('/') => format!("docker.io/{repo}"),
        false => format!("docker.io/library/{repo}"),
    };
    Some(format!("{qualified}@{pin}"))
}

/// A [`Read`] over chunks sent from async code: `Some` bytes, `None` the end. The sender dropped
/// without `None` reads as an error: the delivery was cut off. `progress` is told the bytes taken
/// so far as they are.
pub struct ChunkReader<F: FnMut(u64)> {
    rx: std::sync::mpsc::Receiver<Option<Vec<u8>>>,
    buf: Vec<u8>,
    at: usize,
    taken: u64,
    done: bool,
    progress: F,
}

impl<F: FnMut(u64)> ChunkReader<F> {
    pub fn new(rx: std::sync::mpsc::Receiver<Option<Vec<u8>>>, progress: F) -> Self {
        ChunkReader { rx, buf: vec![], at: 0, taken: 0, done: false, progress }
    }
}

impl<F: FnMut(u64)> Read for ChunkReader<F> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.at == self.buf.len() {
            if self.done {
                return Ok(0);
            }
            match self.rx.recv() {
                Ok(Some(b)) => {
                    self.taken += b.len() as u64;
                    (self.progress)(self.taken);
                    self.buf = b;
                    self.at = 0;
                }
                Ok(None) => self.done = true,
                Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "the image delivery was cut off")),
            }
        }
        let n = out.len().min(self.buf.len() - self.at);
        out[..n].copy_from_slice(&self.buf[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// Image archives for tests.
#[cfg(test)]
pub mod testkit {
    use super::*;

    pub fn sha(b: &[u8]) -> String {
        format!("sha256:{}", hex::encode(Sha256::digest(b)))
    }

    pub struct Img {
        pub entries: Vec<(String, Vec<u8>)>,
        pub manifest: String,
        pub index: String,
    }

    /// A one-layer image (`layer`), a manifest for it, and an index naming it and another
    /// platform's manifest the archive lacks, as `docker save` writes them.
    pub fn image_with(layer: &[u8]) -> Img {
        let layer = layer.to_vec();
        let config = br#"{"rootfs":{"type":"layers","diff_ids":[]},"architecture":"amd64","os":"linux"}"#.to_vec();
        let manifest = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2, "mediaType": MANIFEST_TYPES[0],
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": sha(&config), "size": config.len() },
            "layers": [{ "mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": sha(&layer), "size": layer.len() }],
        }))
        .unwrap();
        let index = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2, "mediaType": INDEX_TYPES[0],
            "manifests": [
                { "mediaType": MANIFEST_TYPES[0], "digest": sha(&manifest), "size": manifest.len() },
                { "mediaType": MANIFEST_TYPES[0], "digest": sha(b"arm64"), "size": 5 },
            ],
        }))
        .unwrap();
        let blob = |b: &[u8]| (format!("blobs/sha256/{}", hex_of(&sha(b)).unwrap()), b.to_vec());
        let (m, i) = (sha(&manifest), sha(&index));
        let top = serde_json::to_vec(&serde_json::json!({"manifests":[{"digest": i, "size": index.len()}]})).unwrap();
        Img {
            entries: vec![
                ("oci-layout".into(), br#"{"imageLayoutVersion":"1.0.0"}"#.to_vec()),
                ("index.json".into(), top),
                ("manifest.json".into(), br#"[{"RepoTags":["evil:latest"]}]"#.to_vec()),
                blob(&layer),
                blob(&config),
                blob(&manifest),
                blob(&index),
                blob(b"unrelated"),
            ],
            manifest: m,
            index: i,
        }
    }

    pub fn archive(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
        let mut b = tar::Builder::new(vec![]);
        for (p, d) in entries {
            let mut h = tar::Header::new_gnu();
            h.set_size(d.len() as u64);
            h.set_mode(0o444);
            h.set_entry_type(tar::EntryType::Regular);
            // Raw, so a test can name what the tar crate's own path setter would refuse.
            h.as_old_mut().name[..p.len()].copy_from_slice(p.as_bytes());
            h.set_cksum();
            b.append(&h, d.as_slice()).unwrap();
        }
        b.into_inner().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;

    fn image() -> Img {
        image_with(b"layer bytes")
    }

    fn tmp() -> tempdir::Dir {
        tempdir::Dir::new()
    }

    mod tempdir {
        pub struct Dir(pub std::path::PathBuf);
        impl Dir {
            pub fn new() -> Dir {
                let p = std::env::temp_dir().join(format!("wicket-oci-test-{}-{}", std::process::id(), ulid::Ulid::new()));
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    fn unpack(entries: &[(String, Vec<u8>)], pin: &str) -> (tempdir::Dir, Result<Unpacked>) {
        let d = tmp();
        let r = unpack_verified(archive(entries).as_slice(), &d.0, pin, Some("docker.io/library/x@sha256:00"), 1 << 30);
        (d, r)
    }

    #[test]
    fn an_index_pin_keeps_its_image_and_drops_the_rest() {
        let img = image();
        let (d, r) = unpack(&img.entries, &img.index);
        let u = r.unwrap();
        assert_eq!((u.media_type.as_str(), u.manifests), (INDEX_TYPES[0], 1));
        let mut kept: Vec<String> =
            std::fs::read_dir(d.0.join("blobs/sha256")).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        kept.sort();
        assert_eq!(kept.len(), 4, "the layer, config, manifest and index: not the unrelated blob");
        assert!(!kept.contains(&hex_of(&sha(b"unrelated")).unwrap().to_string()));
        assert!(!d.0.join("manifest.json").exists(), "the sender's tags are dropped");
        let index: Value = serde_json::from_slice(&std::fs::read(d.0.join("index.json")).unwrap()).unwrap();
        assert_eq!(index["manifests"].as_array().unwrap().len(), 1);
        assert_eq!(index["manifests"][0]["digest"], img.index.as_str());
        assert_eq!(index["manifests"][0]["annotations"]["io.containerd.image.name"], "docker.io/library/x@sha256:00");
    }

    #[test]
    fn a_manifest_pin_works_too() {
        let img = image();
        let (d, r) = unpack(&img.entries, &img.manifest);
        assert_eq!(r.unwrap().media_type, MANIFEST_TYPES[0]);
        assert_eq!(std::fs::read_dir(d.0.join("blobs/sha256")).unwrap().count(), 3);
    }

    #[test]
    fn a_tampered_blob_is_refused() {
        let mut img = image();
        let layer = img.entries.iter_mut().find(|(_, b)| b == b"layer bytes").unwrap();
        layer.1[0] ^= 1;
        let e = unpack(&img.entries, &img.index).1.unwrap_err().to_string();
        assert!(e.contains("does not match its digest"), "{e}");
    }

    #[test]
    fn another_pin_or_a_missing_layer_is_refused() {
        let img = image();
        let e = unpack(&img.entries, &sha(b"something else")).1.unwrap_err().to_string();
        assert!(e.contains("does not hold"), "{e}");
        let without: Vec<_> = img.entries.iter().filter(|(_, b)| b != b"layer bytes").cloned().collect();
        let e = unpack(&without, &img.index).1.unwrap_err().to_string();
        assert!(e.contains("lacks"), "{e}");
        // An index whose only manifest is missing has no image.
        let without: Vec<_> = img.entries.iter().filter(|(p, _)| !p.ends_with(hex_of(&img.manifest).unwrap())).cloned().collect();
        let e = unpack(&without, &img.index).1.unwrap_err().to_string();
        assert!(e.contains("no complete image"), "{e}");
    }

    #[test]
    fn odd_entries_are_refused() {
        let img = image();
        for bad in ["../etc/passwd", "blobs/sha256/../../x", "blobs/sha256/abc", "blobs/sha512/".to_string().as_str(), "/abs"] {
            let mut es = img.entries.clone();
            es.push((bad.into(), b"x".to_vec()));
            assert!(unpack(&es, &img.index).1.is_err(), "{bad}");
        }
        let mut es = img.entries.clone();
        es.push(es[3].clone());
        let e = unpack(&es, &img.index).1.unwrap_err().to_string();
        assert!(e.contains("twice"), "{e}");
        // A symlink.
        let mut b = tar::Builder::new(vec![]);
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        b.append_link(&mut h, "index.json", "/etc/passwd").unwrap();
        let d = tmp();
        let e = unpack_verified(b.into_inner().unwrap().as_slice(), &d.0, &img.index, None, 1 << 30).unwrap_err().to_string();
        assert!(e.contains("not a regular file"), "{e}");
    }

    #[test]
    fn a_config_pin_says_why() {
        let img = image();
        let config = &img.entries.iter().find(|(_, b)| b.starts_with(br#"{"rootfs""#)).unwrap().1;
        let e = unpack(&img.entries, &sha(config)).1.unwrap_err().to_string();
        assert!(e.contains("config digest"), "{e}");
    }

    #[test]
    fn the_cap_holds() {
        let img = image();
        let d = tmp();
        let e = unpack_verified(archive(&img.entries).as_slice(), &d.0, &img.index, None, 16).unwrap_err().to_string();
        assert!(e.contains("larger than"), "{e}");
    }

    #[test]
    fn import_names_are_qualified() {
        let p = format!("sha256:{}", "a".repeat(64));
        assert_eq!(import_name("ubuntu:24.04", &p).unwrap(), format!("docker.io/library/ubuntu@{p}"));
        assert_eq!(import_name("wicket/claude-code:abc", &p).unwrap(), format!("docker.io/wicket/claude-code@{p}"));
        assert_eq!(import_name(&format!("registry.example.com:5000/x/y@{p}"), &p).unwrap(), format!("registry.example.com:5000/x/y@{p}"));
        assert_eq!(import_name(&p, &p), None);
    }

    #[test]
    fn a_cut_off_delivery_reads_as_an_error() {
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Some(b"abc".to_vec())).unwrap();
        drop(tx);
        let mut seen = 0;
        let mut r = ChunkReader::new(rx, |n| seen = n);
        let mut s = String::new();
        assert!(r.read_to_string(&mut s).is_err());
        assert_eq!(seen, 3);
        let (tx, rx) = std::sync::mpsc::channel();
        tx.send(Some(b"abc".to_vec())).unwrap();
        tx.send(None).unwrap();
        let mut s = String::new();
        ChunkReader::new(rx, |_| {}).read_to_string(&mut s).unwrap();
        assert_eq!(s, "abc");
    }
}
