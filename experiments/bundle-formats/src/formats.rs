//! The three bundle formats, each as wicket would integrate it.
//!
//! - `today`: `wicket_store::bundle::push`/`pull_tree` (tar + zstd -3, one blob per tree, reused
//!   while the tree's digest is unchanged) over `SealedStore` (AES-256-GCM, 64 KiB chunks).
//! - `age`: the same push and pull, over `AgeStore` instead of `SealedStore`.
//! - `rustic`: the restic repository format through `rustic_core`: content-defined chunks,
//!   deduplicated within a repository, packs, an index, snapshots; one repository per agent (or per
//!   zone, `--repo-key zone`), each tree a snapshot with `as_path` `/<tree>`, host the agent.

use crate::store::{self, Spec};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use std::io::Read;
use std::path::{Path, PathBuf};
use wicket_store::bundle::{self, PushTo, StateManifest, TreeSrc};
use wicket_store::objects::ObjectStore;
use wicket_store::sealed::SealedStore;

pub trait Format {
    /// Saves `trees` (name, directory) as the agent's next state.
    fn save(&self, agent: &str, trees: &[(String, PathBuf)]) -> Result<Value>;
    /// Restores the agent's latest state (or one tree of it) under `dest/<tree>`.
    fn restore(&self, agent: &str, tree: Option<&str>, dest: &Path) -> Result<Value>;
    /// Keeps the newest `keep` states, and reclaims what nothing kept refers to.
    fn prune(&self, agent: &str, keep: usize) -> Result<Value>;
    /// Checks the repository's integrity (reading every byte, with `read_data`).
    fn check(&self, agent: &str, read_data: bool) -> Result<Value>;
}

/// A per-agent key for the experiment (derived, so runs are repeatable).
pub fn agent_key(agent: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(format!("e5 agent key {agent}").as_bytes()).into()
}

pub fn open(format: &str, spec: &Spec, scratch: &Path, repo_key: &str) -> Result<Box<dyn Format>> {
    Ok(match format {
        "today" | "age" => Box::new(Ours { spec: spec.clone(), scratch: scratch.to_path_buf(), age: format == "age" }),
        "rustic" => Box::new(Rustic { spec: spec.clone(), repo_key: repo_key.to_string() }),
        other => bail!("unknown format {other}"),
    })
}

// ---- today / age ----

struct Ours {
    spec: Spec,
    scratch: PathBuf,
    age: bool,
}

impl Ours {
    fn store(&self, agent: &str) -> Result<Box<dyn ObjectStore>> {
        let inner = store::open(&self.spec, &self.scratch)?;
        Ok(if self.age {
            let id = age_identity(agent);
            Box::new(store::AgeStore::new(inner, id, self.scratch.clone()))
        } else {
            Box::new(SealedStore::new(inner, &agent_key(agent)))
        })
    }

    /// The agent's manifests, oldest first: (seq, generation, key).
    fn manifests(s: &dyn ObjectStore, agent: &str) -> Result<Vec<(i64, i64, String)>> {
        let mut v: Vec<(i64, i64, String)> = s
            .list_prefix(&format!("a/{agent}/m/"))?
            .into_iter()
            .filter_map(|k| {
                let (seq, gen) = k.rsplit('/').next()?.split_once('.')?;
                Some((seq.parse().ok()?, gen.parse().ok()?, k))
            })
            .collect();
        v.sort();
        Ok(v)
    }
}

fn age_identity(agent: &str) -> age::x25519::Identity {
    // Derived from the agent key, so a later process opens the same objects.
    let k = agent_key(agent);
    let s = bech32_identity(&k);
    s.parse().expect("an age identity")
}

/// `AGE-SECRET-KEY-1…` for 32 secret bytes (bech32, upper case).
fn bech32_identity(k: &[u8; 32]) -> String {
    const CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    fn polymod(v: &[u8]) -> u32 {
        let g = [0x3b6a57b2u32, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        let mut chk = 1u32;
        for b in v {
            let top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ u32::from(*b);
            for (i, gi) in g.iter().enumerate() {
                if (top >> i) & 1 == 1 {
                    chk ^= gi;
                }
            }
        }
        chk
    }
    let hrp = "age-secret-key-";
    let mut data = vec![];
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in k {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        data.push(((acc << (5 - bits)) & 31) as u8);
    }
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v.extend(&data);
    v.extend([0u8; 6]);
    let pm = polymod(&v) ^ 1;
    let mut s = format!("{hrp}1");
    for d in &data {
        s.push(CHARSET[*d as usize] as char);
    }
    for i in 0..6 {
        s.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    s.to_uppercase()
}

impl Format for Ours {
    fn save(&self, agent: &str, trees: &[(String, PathBuf)]) -> Result<Value> {
        let s = self.store(agent)?;
        let ms = Self::manifests(s.as_ref(), agent)?;
        let prev: Option<StateManifest> = match ms.last() {
            Some((_, _, k)) => Some(bundle::read_manifest(s.as_ref(), k, agent)?),
            None => None,
        };
        let seq = ms.last().map_or(1, |m| m.0 + 1);
        let gen = std::env::var("E5_GENERATION").ok().and_then(|g| g.parse().ok()).unwrap_or(1);
        let srcs: Vec<TreeSrc> = trees.iter().map(|(n, p)| TreeSrc { name: n.clone(), path: p.clone(), exclude: &[] }).collect();
        let (m, key) = bundle::push(s.as_ref(), &PushTo { agent, generation: gen, seq, session_id: "e5" }, &srcs, prev.as_ref(), &self.scratch)?;
        let reused: Vec<&str> =
            m.trees.iter().filter(|t| prev.as_ref().and_then(|p| p.tree(&t.name)).is_some_and(|pt| pt.blob == t.blob)).map(|t| t.name.as_str()).collect();
        Ok(json!({ "manifest": key, "seq": seq, "raw_bytes": m.raw_bytes(), "stored_bytes": m.stored_bytes(), "trees_reused": reused }))
    }

    fn restore(&self, agent: &str, tree: Option<&str>, dest: &Path) -> Result<Value> {
        let s = self.store(agent)?;
        let (_, _, key) = Self::manifests(s.as_ref(), agent)?.pop().ok_or_else(|| anyhow!("no state for {agent}"))?;
        let m = bundle::read_manifest(s.as_ref(), &key, agent)?;
        let mut n = 0;
        for t in m.trees.iter().filter(|t| tree.is_none_or(|w| w == t.name)) {
            bundle::pull_tree(s.as_ref(), t, &dest.join(&t.name))?;
            n += 1;
        }
        if n == 0 {
            bail!("no tree {tree:?} in {key}");
        }
        Ok(json!({ "manifest": key, "trees": n }))
    }

    fn prune(&self, agent: &str, keep: usize) -> Result<Value> {
        let s = self.store(agent)?;
        let ms = Self::manifests(s.as_ref(), agent)?;
        let cut = ms.len().saturating_sub(keep);
        let mut live = std::collections::HashSet::new();
        for (_, _, k) in &ms[cut..] {
            for t in bundle::read_manifest(s.as_ref(), k, agent)?.trees {
                live.insert(t.blob);
            }
        }
        let mut deleted = 0;
        for (_, _, k) in &ms[..cut] {
            s.delete(k)?;
            deleted += 1;
        }
        for b in s.list_prefix(&format!("a/{agent}/p/"))? {
            if !live.contains(&b) {
                s.delete(&b)?;
                deleted += 1;
            }
        }
        Ok(json!({ "deleted_objects": deleted, "kept_manifests": ms.len() - cut }))
    }

    fn check(&self, agent: &str, read_data: bool) -> Result<Value> {
        let s = self.store(agent)?;
        let (mut blobs, mut bytes, mut bad) = (0u64, 0u64, vec![]);
        for (_, _, k) in Self::manifests(s.as_ref(), agent)? {
            let m = bundle::read_manifest(s.as_ref(), &k, agent)?;
            for t in m.trees {
                blobs += 1;
                match s.get(&t.blob)? {
                    None => bad.push(format!("{} missing", t.blob)),
                    Some(mut r) if read_data => {
                        // The blob's hash (its name) and the AEAD tags, as a restore would see them.
                        use sha2::Digest;
                        let mut h = sha2::Sha256::new();
                        let mut buf = vec![0u8; 1 << 16];
                        loop {
                            match r.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    h.update(&buf[..n]);
                                    bytes += n as u64;
                                }
                                Err(e) => {
                                    bad.push(format!("{}: {e}", t.blob));
                                    break;
                                }
                            }
                        }
                        if !t.blob.ends_with(&hex::encode(h.finalize())) {
                            bad.push(format!("{} does not match its hash", t.blob));
                        }
                    }
                    Some(_) => {}
                }
            }
        }
        Ok(json!({ "blobs": blobs, "bytes_read": bytes, "errors": bad }))
    }
}

// ---- rustic ----

struct Rustic {
    spec: Spec,
    /// `agent` (a repository per agent) or a zone name (one shared repository).
    repo_key: String,
}

impl Rustic {
    fn repo_name(&self, agent: &str) -> String {
        if self.repo_key == "agent" { format!("r-{agent}") } else { format!("z-{}", self.repo_key) }
    }

    fn password(&self, agent: &str) -> String {
        let who = if self.repo_key == "agent" { agent.to_string() } else { format!("zone {}", self.repo_key) };
        hex::encode(agent_key(&who))
    }

    fn open(&self, agent: &str) -> Result<rustic_core::Repository<rustic_core::OpenStatus>> {
        use rustic_backend::BackendOptions;
        use rustic_core::{ConfigOptions, Credentials, KeyOptions, Repository, RepositoryOptions};
        let name = self.repo_name(agent);
        let backends = match &self.spec {
            Spec::Fs(d) => BackendOptions::default().repository(d.join(&name).to_string_lossy().to_string()).to_backends()?,
            Spec::S3 { endpoint, bucket, prefix } => {
                let (k, s) = store::creds();
                let mut o = std::collections::BTreeMap::new();
                o.insert("bucket".to_string(), bucket.clone());
                o.insert("endpoint".to_string(), endpoint.clone());
                o.insert("region".to_string(), "us-east-1".to_string());
                o.insert("root".to_string(), format!("/{prefix}{name}"));
                o.insert("access_key_id".to_string(), k);
                o.insert("secret_access_key".to_string(), s);
                o.insert("enable_virtual_host_style".to_string(), "false".to_string());
                BackendOptions::default().repository("opendal:s3").options(o).to_backends()?
            }
        };
        let creds = Credentials::password(self.password(agent));
        let repo = Repository::new(&RepositoryOptions::default(), &backends)?;
        match repo.open(&creds) {
            Ok(r) => Ok(r),
            Err(_) => {
                let repo = Repository::new(&RepositoryOptions::default(), &backends)?;
                Ok(repo.init(&creds, &KeyOptions::default(), &ConfigOptions::default())?)
            }
        }
    }
}

fn tag(name: &str) -> String {
    format!("tree={name}")
}

impl Format for Rustic {
    fn save(&self, agent: &str, trees: &[(String, PathBuf)]) -> Result<Value> {
        use rustic_core::{BackupOptions, PathList, SnapshotOptions};
        let repo = self.open(agent)?.to_indexed_ids()?;
        let mut out = vec![];
        for (name, path) in trees {
            let snap = SnapshotOptions::default().host(agent.to_string()).add_tags(&tag(name))?.to_snapshot()?;
            let opts = BackupOptions::default().as_path(PathBuf::from(format!("/{name}")));
            let source = PathList::from_string(&path.to_string_lossy())?.sanitize()?;
            let sn = repo.backup(&opts, &source, snap)?;
            let s = sn.summary.as_ref().context("summary")?;
            out.push(json!({ "tree": name, "id": sn.id.to_string(), "files_new": s.files_new, "files_changed": s.files_changed,
                "data_added": s.data_added, "data_added_packed": s.data_added_packed, "bytes_processed": s.total_bytes_processed }));
        }
        Ok(json!({ "snapshots": out }))
    }

    fn restore(&self, agent: &str, tree: Option<&str>, dest: &Path) -> Result<Value> {
        use rustic_core::{LocalDestination, LsOptions, RestoreOptions};
        let repo = self.open(agent)?.to_indexed()?;
        let names: Vec<String> = match tree {
            Some(t) => vec![t.to_string()],
            None => {
                let mut v: Vec<String> = repo
                    .get_all_snapshots()?
                    .into_iter()
                    .filter(|s| s.hostname == agent)
                    .flat_map(|s| s.tags.iter().filter_map(|t| t.strip_prefix("tree=").map(String::from)).collect::<Vec<_>>())
                    .collect();
                v.sort();
                v.dedup();
                v
            }
        };
        for name in &names {
            let want = tag(name);
            let node = repo.node_from_snapshot_path(&format!("latest:/{name}"), |s| s.hostname == agent && s.tags.contains(&want))?;
            // Wicket's rules, checked on the snapshot's tree before anything is written (see RESULTS §5).
            let ls = repo.ls(&node, &LsOptions::default())?;
            let mut rules = crate::safety::Listing::default();
            for item in ls.clone() {
                let (p, n) = item?;
                if let Err(why) = rules.check(&p, &n) {
                    bail!("tree {name}: refused: {why}");
                }
            }
            let to = dest.join(name);
            let d = LocalDestination::new(&to.to_string_lossy(), true, !node.is_dir())?;
            let opts = RestoreOptions::default();
            let plan = repo.prepare_restore(&opts, ls.clone(), &d, false)?;
            repo.restore(plan, &opts, ls, &d)?;
        }
        Ok(json!({ "trees": names.len() }))
    }

    fn prune(&self, agent: &str, keep: usize) -> Result<Value> {
        use rustic_core::PruneOptions;
        let repo = self.open(agent)?;
        let mut snaps: Vec<_> = repo.get_all_snapshots()?.into_iter().filter(|s| s.hostname == agent).collect();
        snaps.sort_by_key(|s| s.time.clone());
        // Keep the newest `keep` per tree.
        let mut by_tree: std::collections::BTreeMap<String, Vec<_>> = Default::default();
        for s in snaps {
            let k = s.tags.iter().find(|t| t.starts_with("tree=")).cloned().unwrap_or_default();
            by_tree.entry(k).or_default().push(s);
        }
        let mut gone = vec![];
        for (_, v) in by_tree {
            let cut = v.len().saturating_sub(keep);
            gone.extend(v[..cut].iter().map(|s| s.id));
        }
        repo.delete_snapshots(&gone)?;
        let repo = repo.to_indexed_ids()?;
        let opts = PruneOptions::default().instant_delete(true);
        let plan = repo.prune_plan(&opts)?;
        let stats = format!("{:?}", plan.stats);
        repo.prune(&opts, plan)?;
        Ok(json!({ "forgotten_snapshots": gone.len(), "plan": stats }))
    }

    fn check(&self, agent: &str, read_data: bool) -> Result<Value> {
        use rustic_core::CheckOptions;
        let repo = self.open(agent)?;
        let res = repo.check(CheckOptions::default().read_data(read_data))?;
        Ok(json!({ "result": format!("{res:?}") }))
    }
}
