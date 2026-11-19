//! Keeping per-node services running (#579 step 3), each reconcile pass: one instance of each
//! installed service on each node whose boxes use it, per tenant (or one shared, when the service
//! says `tenancy: shared`). An instance is an ordinary run of the service's program, owned by
//! wicket, started from the service's snapshot. Users reach it through links (`zone.uses`), with its
//! reach (see `wicket_core::service`).
//!
//! - **Installed from a snapshot** ([`snapshot`]): `wicket service add` copies the manifest and its
//!   program's source into `services/<name>/<sha256>/` under the data directory, pins the source's
//!   digest into the copy, and records its sha256. Nothing later written to the file it came from
//!   changes what runs.
//! - **Started** when a live run wants one and none is live, on an active node its `node_selector`
//!   matches and that isn't past its lease (a node kept past its lease bills by the hour). Again
//!   after it ends, with a delay that doubles with each instance that didn't last
//!   ([`restart_delay`]).
//! - **Stopped** (revoked) after [`IDLE_SECS`] with no live run wanting it, and all of them when the
//!   service is removed. An instance never holds a capacity lease's node by itself.

use crate::data_dir;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use wicket_core::service::{ServiceSpec, Tenancy};
use wicket_store::Ledger;

/// The shortest wait before another instance is started where one ended.
pub const RESTART_AFTER_SECS: i64 = 60;

/// An instance no live run has wanted for this long is stopped.
pub const IDLE_SECS: i64 = 600;

/// Who stops instances, as their revocation records it.
pub const BY: &str = "wicket:services";

/// A node as the service loop sees it.
#[derive(Clone, Debug, Default)]
pub struct NodeView {
    pub name: String,
    pub active: bool,
    /// A capacity lease's node past its lease's end: nothing new starts on it.
    pub past_lease: bool,
    pub labels: BTreeMap<String, String>,
}

/// An installed service, as the loop reads it from its snapshot.
#[derive(Clone, Debug)]
pub struct Installed {
    pub spec: ServiceSpec,
    pub manifest: String,
    pub sha256: String,
    pub tenant: String,
    /// The snapshot's zone and program: what its instances' identities say.
    pub zone: String,
    pub program: String,
}

/// An instance to start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Start {
    pub service: String,
    pub node: String,
    pub tenant: String,
}

/// How long to wait before starting another instance after `failed` instances in a row ended
/// (newest first, the last one under 10 minutes old): 60 s, doubling, at most an hour.
pub fn restart_delay(failed: usize) -> i64 {
    (RESTART_AFTER_SECS << failed.saturating_sub(1).min(6)).min(3600)
}

/// What to start, given the installed services, what live runs want (service, node, tenant), the
/// nodes, and each (service, node, tenant)'s instances (newest first). Pure: the pass's decision.
pub fn plan(
    services: &BTreeMap<String, Installed>,
    demand: &[(String, String, String)],
    nodes: &[NodeView],
    instances: &dyn Fn(&str, &str, &str) -> Vec<wicket_store::Instance>,
    now: i64,
) -> Vec<Start> {
    let mut out: Vec<Start> = vec![];
    for (service, node, tenant) in demand {
        let Some(svc) = services.get(service) else { continue };
        let Some(n) = nodes.iter().find(|n| &n.name == node && n.active && !n.past_lease) else { continue };
        if !svc.spec.node_selector.iter().all(|(k, v)| n.labels.get(k) == Some(v)) {
            continue;
        }
        // Single-tenant for now: an instance runs as the service's tenant, so only its tenant's
        // boxes are served (a shared one serves every tenant).
        let tenant = match svc.spec.tenancy {
            Tenancy::Shared => wicket_store::SHARED_TENANT.to_string(),
            Tenancy::PerTenant if *tenant == svc.tenant => tenant.clone(),
            Tenancy::PerTenant => continue,
        };
        let have = instances(service, node, &tenant);
        if have.iter().any(|i| i.live) {
            continue;
        }
        // Instances that ended within 10 minutes of starting, in a row: each one doubles the wait.
        let failed = have.iter().take_while(|i| now - i.started_at < 600 + restart_delay(7)).count();
        if have.first().is_some_and(|i| now - i.started_at < restart_delay(failed)) {
            continue;
        }
        let s = Start { service: service.clone(), node: node.clone(), tenant };
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

/// What one pass did.
#[derive(Debug, Default)]
pub struct Passed {
    pub started: Vec<(Start, String)>,
    pub stopped: Vec<(String, String)>,
    pub failed: Vec<(Start, String)>,
}

/// The installed services, from their snapshots (one that doesn't load is said and left out).
pub fn installed(l: &Ledger) -> Result<BTreeMap<String, Installed>> {
    let mut out = BTreeMap::new();
    for s in l.services()? {
        let loaded = std::fs::read_to_string(&s.manifest).map_err(anyhow::Error::from).and_then(|t| {
            let sha = hex::encode(Sha256::digest(t.as_bytes()));
            anyhow::ensure!(sha == s.sha256, "its snapshot changed after it was installed (sha256 {sha}, installed {})", s.sha256);
            Ok(wicket_core::Manifest::from_yaml(&t)?)
        });
        match loaded {
            Ok(m) if m.service.is_some() => {
                out.insert(
                    s.name.clone(),
                    Installed {
                        spec: m.service.clone().expect("checked"),
                        manifest: s.manifest.clone(),
                        sha256: s.sha256.clone(),
                        tenant: s.tenant.clone(),
                        zone: m.zone.name.clone(),
                        program: m.program.as_ref().map(|p| p.name.clone()).unwrap_or_default(),
                    },
                );
            }
            Ok(_) => say_err!("[wicket] service {}: its snapshot {} isn't a service", s.name, s.manifest),
            Err(e) => say_err!("[wicket] service {}: its snapshot {} doesn't load: {e:#}", s.name, s.manifest),
        }
    }
    Ok(out)
}

/// One pass: idle instances stopped, and what [`plan`] says started.
pub fn pass(l: &Ledger, dry_run: bool) -> Result<Passed> {
    let now = wicket_store::now();
    let services = installed(l)?;
    let nodes: Vec<NodeView> = l
        .nodes()?
        .into_iter()
        .map(|n| NodeView {
            active: n.status == "active",
            past_lease: crate::nodecreate::refuse_past_lease(l, &n.name, now).is_err(),
            labels: l.node_labels(&n.name).unwrap_or_default(),
            name: n.name,
        })
        .collect();
    let demand = l.service_demand()?;
    let mut done = Passed::default();
    if !dry_run {
        for (service, node, tenant) in &demand {
            let tenant = match services.get(service).map(|s| s.spec.tenancy) {
                Some(Tenancy::Shared) => wicket_store::SHARED_TENANT,
                _ => tenant.as_str(),
            };
            l.touch_service_instances(service, node, tenant, now)?;
        }
        for i in l.live_service_instances()? {
            let idle = now - i.wanted_at >= IDLE_SECS;
            let gone = !services.contains_key(&i.service);
            if idle || gone {
                let why = if gone {
                    "its service was removed".to_string()
                } else {
                    format!("no box on {} has used it for {} s", i.node, IDLE_SECS)
                };
                stop(l, &i, &why)?;
                done.stopped.push((i.run.clone(), why));
            }
        }
    }
    let starts = plan(&services, &demand, &nodes, &|s, n, t| l.service_instances(s, n, t).unwrap_or_default(), now);
    for s in starts {
        if dry_run {
            done.started.push((s, String::new()));
            continue;
        }
        let svc = &services[&s.service];
        let run = wicket_core::RunId::new();
        l.record_service_instance(&run.0, &s.service, &s.node, &s.tenant, &svc.sha256, now)?;
        let started = start(&svc.manifest, &s, &run.0);
        let body = serde_json::json!({
            "service": s.service, "node": s.node, "tenant": s.tenant, "run": run.0, "sha256": svc.sha256,
            "error": started.as_ref().err().map(|e| format!("{e:#}")),
        });
        let _ = l.audit(&wicket_core::TenantId(svc.tenant.clone()), Some(&run), "service.instance_started", &body);
        match started {
            Ok(()) => done.started.push((s, run.0)),
            // The next pass tries again (after its delay): one failed start doesn't stop the rest.
            Err(e) => done.failed.push((s, format!("{e:#}"))),
        }
    }
    Ok(done)
}

/// `wicket service remove`: the service's live instances stop (their runs are revoked), then its
/// row goes, audited under its tenant with what was stopped. Returns how many were stopped.
pub fn remove(l: &Ledger, name: &str, by: &str) -> Result<usize> {
    let row = l.services()?.into_iter().find(|s| s.name == name).with_context(|| format!("no service {name} is installed"))?;
    let live: Vec<_> = l.live_service_instances()?.into_iter().filter(|i| i.service == name).collect();
    for i in &live {
        stop(l, i, "its service was removed")?;
    }
    let tenant = wicket_core::TenantId(row.tenant.clone());
    l.immediate::<_, anyhow::Error>(|l| {
        l.remove_service(name)?;
        l.audit(
            &tenant,
            None,
            "service.removed",
            &serde_json::json!({ "name": name, "sha256": row.sha256, "stopped": live.iter().map(|i| &i.run).collect::<Vec<_>>(), "by": by }),
        )?;
        Ok(())
    })?;
    Ok(live.len())
}

/// Stops an instance: its run is revoked (its supervisor stops its box), audited.
pub fn stop(l: &Ledger, i: &wicket_store::Instance, why: &str) -> Result<()> {
    l.revoke(&i.run, BY, why)?;
    l.audit(
        &wicket_core::TenantId::single(),
        Some(&wicket_core::RunId(i.run.clone())),
        "service.instance_stopped",
        &serde_json::json!({ "service": i.service, "node": i.node, "tenant": i.tenant, "run": i.run, "why": why }),
    )?;
    Ok(())
}

/// Starts an instance: `wicket run [--node <node>] --run-id <run> <snapshot manifest>`, detached,
/// its output in `services/<name>/<run>.log` under the data directory. This host's own node takes
/// no `--node`.
fn start(manifest: &str, s: &Start, run: &str) -> Result<()> {
    let dir = data_dir().join("services").join(&s.service).join("logs");
    std::fs::create_dir_all(&dir)?;
    let log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join(format!("{run}.log")))?;
    let exe = wicket_node::reexec::self_exe()?;
    let mut c = std::process::Command::new(exe);
    c.arg("run");
    if s.node != crate::localnode::NAME {
        c.args(["--node", &s.node]);
    }
    c.args(["--run-id", run, manifest]).stdin(std::process::Stdio::null());
    c.stdout(log.try_clone()?);
    c.stderr(log);
    wicket_node::reexec::detach(&mut c);
    c.spawn().context("spawning wicket run")?;
    Ok(())
}

/// A service's snapshot: its manifest (with its source's digest pinned), where it was written, and
/// the manifest's sha256.
#[derive(Debug)]
pub struct Snapshot {
    pub manifest: wicket_core::Manifest,
    pub path: PathBuf,
    pub sha256: String,
}

/// Copies the service at `manifest` into `services/<name>/<sha256>/` under `root` (the data
/// directory): its program's source as `source/` (plain files only, its digest pinned in the copy's
/// manifest, so a start refuses any other), and the manifest as `manifest.yaml`.
pub fn snapshot(manifest: &Path, root: &Path) -> Result<Snapshot> {
    let path = std::fs::canonicalize(manifest).with_context(|| format!("reading {}", manifest.display()))?;
    let mut m = wicket_core::Manifest::from_yaml(&std::fs::read_to_string(&path)?)?;
    let svc = m.service.clone().context("this manifest has no service: section: it is not a per-node service")?;
    if svc.drain == wicket_core::service::Drain::Keep {
        bail!("service.drain: keep isn't supported yet: an instance's volumes go with its node when the node is released (drain: drop)");
    }
    if m.zone.escalation.request {
        bail!("a service's zone may not ask for more (escalation.request: true): it would ask on behalf of every box that uses it");
    }
    let name = m.program.as_ref().context("a service is a program")?.name.clone();
    wicket_core::service::check_name(&name).map_err(anyhow::Error::msg)?;
    let _ = svc;
    let base = root.join("services").join(&name);
    let staging = base.join(format!(".staging-{}", std::process::id()));
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(&staging)?;
    let p = m.program.as_mut().expect("checked");
    if let Some(src) = p.source.clone() {
        let from = path.parent().unwrap_or(Path::new("/")).join(&src);
        copy_plain(&from, &staging.join("source")).with_context(|| format!("copying its source {}", from.display()))?;
        let digest = wicket_home::program::digest_dir(&staging.join("source"))?;
        if let Some(pin) = &p.digest {
            anyhow::ensure!(*pin == digest, "its source isn't the one its manifest pins ({pin}; it is {digest})");
        }
        p.source = Some("source".into());
        p.digest = Some(digest);
    }
    let yaml = wicket_core::yaml::to_string(&m)?;
    let sha256 = hex::encode(Sha256::digest(yaml.as_bytes()));
    std::fs::write(staging.join("manifest.yaml"), &yaml)?;
    let dir = base.join(&sha256);
    if dir.exists() {
        std::fs::remove_dir_all(&staging)?;
    } else {
        std::fs::rename(&staging, &dir)?;
    }
    Ok(Snapshot { manifest: m, path: dir.join("manifest.yaml"), sha256 })
}

/// Copies the tree at `from` to `to`: directories and regular files only (a symlink or any other
/// file is refused), keeping the executable bit.
fn copy_plain(from: &Path, to: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(to)?;
    for e in std::fs::read_dir(from)? {
        let e = e?;
        let meta = std::fs::symlink_metadata(e.path())?;
        let dest = to.join(e.file_name());
        if meta.is_dir() {
            copy_plain(&e.path(), &dest)?;
        } else if meta.is_file() {
            std::fs::copy(e.path(), &dest)?;
            let exec = meta.permissions().mode() & 0o111 != 0;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(if exec { 0o755 } else { 0o644 }))?;
        } else {
            bail!("{}: only directories and plain files are copied (a symlink or special file isn't)", e.path().display());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_store::Instance;

    fn svc(y: &str, tenant: &str) -> Installed {
        Installed {
            spec: wicket_core::yaml::from_str(y).unwrap(),
            manifest: "/m".into(),
            sha256: "aa".into(),
            tenant: tenant.into(),
            zone: "z".into(),
            program: "p".into(),
        }
    }

    fn inst(started_at: i64, live: bool) -> Instance {
        Instance {
            run: "run_i".into(),
            service: "s".into(),
            node: "n".into(),
            tenant: "t".into(),
            started_at,
            sha256: "aa".into(),
            wanted_at: started_at,
            live,
        }
    }

    /// The example (examples/services/npm-cache) is a valid service: per tenant, read-only reach of
    /// the public registry, and the env that points npm at it; and it snapshots.
    #[test]
    fn the_npm_cache_example_is_a_per_tenant_service() {
        let path = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/services/npm-cache/manifest.yaml"));
        let m = wicket_core::Manifest::from_yaml(&std::fs::read_to_string(path).unwrap()).unwrap();
        let s = m.service.as_ref().unwrap();
        assert_eq!((s.port, s.tenancy, s.public_only), (4873, Tenancy::PerTenant, false));
        assert_eq!(s.user_env("npm-cache")["npm_config_registry"], "http://npm-cache.wicket.internal:4873/");
        assert!(m.zone.reach.iter().all(|r| r.host == "registry.npmjs.org" && r.methods.iter().all(|x| x == "GET" || x == "HEAD")));
        let root = std::env::temp_dir().join(format!("wicket-svc-example-{}", std::process::id()));
        let snap = snapshot(path, &root).unwrap();
        for f in ["config.yaml", "package.json", "package-lock.json", "start.sh"] {
            assert!(snap.path.parent().unwrap().join("source").join(f).is_file(), "{f} in the snapshot");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn one_instance_per_service_node_and_tenant_that_something_wants() {
        let services = BTreeMap::from([
            ("npm-cache".to_string(), svc("port: 4873", "t0")),
            ("oci-mirror".to_string(), svc("port: 5000\ntenancy: shared\npublic_only: true\nnode_selector: { pool: build }", "t0")),
        ]);
        let nodes = vec![
            NodeView { name: "n1".into(), active: true, labels: BTreeMap::from([("pool".into(), "build".into())]), ..Default::default() },
            NodeView { name: "n2".into(), active: true, ..Default::default() },
            NodeView { name: "gone".into(), active: false, ..Default::default() },
            NodeView { name: "billed".into(), active: true, past_lease: true, ..Default::default() },
            NodeView { name: "local".into(), active: true, ..Default::default() },
        ];
        let d = |s: &str, n: &str, t: &str| (s.to_string(), n.to_string(), t.to_string());
        let demand = vec![
            d("npm-cache", "n1", "t0"),
            d("npm-cache", "n1", "t1"),
            d("npm-cache", "gone", "t0"),
            d("npm-cache", "billed", "t0"),
            d("npm-cache", "local", "t0"),
            d("oci-mirror", "n1", "t0"),
            d("oci-mirror", "n1", "t1"),
            d("oci-mirror", "n2", "t0"),
            d("not-installed", "n1", "t0"),
        ];
        let none = |_: &str, _: &str, _: &str| vec![];
        let got = plan(&services, &demand, &nodes, &none, 100_000);
        let s = |s: &str, n: &str, t: &str| Start { service: s.into(), node: n.into(), tenant: t.into() };
        assert_eq!(
            got,
            vec![s("npm-cache", "n1", "t0"), s("npm-cache", "local", "t0"), s("oci-mirror", "n1", "*")],
            "the service's tenant only (single-tenant); shared once per node; only active nodes its selector \
             matches, never one past its lease; this host's own node too"
        );
    }

    /// #579's review: a start that never made its run counts as gone (the store's START_GRACE_SECS),
    /// and the wait before the next grows with each instance that didn't last.
    #[test]
    fn a_failing_service_is_retried_ever_more_slowly() {
        let services = BTreeMap::from([("npm-cache".to_string(), svc("port: 4873", "t0"))]);
        let nodes = vec![NodeView { name: "n1".into(), active: true, ..Default::default() }];
        let demand = vec![("npm-cache".to_string(), "n1".to_string(), "t0".to_string())];
        let now = 100_000;
        let live = |_: &str, _: &str, _: &str| vec![inst(now - 10, true)];
        assert!(plan(&services, &demand, &nodes, &live, now).is_empty(), "a live one is kept");
        let one = |_: &str, _: &str, _: &str| vec![inst(now - 30, false)];
        assert!(plan(&services, &demand, &nodes, &one, now).is_empty(), "the first retry waits 60 s");
        let one_later = |_: &str, _: &str, _: &str| vec![inst(now - 61, false)];
        assert_eq!(plan(&services, &demand, &nodes, &one_later, now).len(), 1);
        let three = |_: &str, _: &str, _: &str| vec![inst(now - 200, false), inst(now - 400, false), inst(now - 500, false)];
        assert!(plan(&services, &demand, &nodes, &three, now).is_empty(), "three in a row: 240 s");
        assert_eq!((restart_delay(1), restart_delay(3), restart_delay(20)), (60, 240, 3600));
    }

    /// #579's review, 3 and 9: an instance no box has used for IDLE_SECS is stopped by a pass, and
    /// removing its service stops its instances; both are audited.
    #[test]
    fn idle_instances_stop_and_removing_a_service_stops_its_instances() {
        let root = std::env::temp_dir().join(format!("wicket-svc-idle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("m.yaml");
        std::fs::write(&path, "task: c\nprogram: { name: npm-cache, command: [x] }\nservice: { port: 4873 }\nzone: { name: npm-cache }\n")
            .unwrap();
        let snap = snapshot(&path, &root.join("data")).unwrap();
        let l = Ledger::open_in_memory().unwrap();
        l.add_service("npm-cache", &snap.path.display().to_string(), &snap.sha256, "t0", "alex").unwrap();
        let t = wicket_core::TenantId::single();
        let now = wicket_store::now();
        for run in ["run_idle", "run_busy"] {
            l.run_started(&t, &wicket_core::RunId(run.into()), "npm-cache", "npm-cache").unwrap();
        }
        l.record_service_instance("run_idle", "npm-cache", "n1", "t0", &snap.sha256, now - IDLE_SECS - 5).unwrap();
        l.record_service_instance("run_busy", "npm-cache", "n2", "t0", &snap.sha256, now - IDLE_SECS - 5).unwrap();
        // A live user on n2 keeps its instance wanted.
        l.run_started(&t, &wicket_core::RunId("run_user".into()), "build", "build").unwrap();
        l.want_service("npm-cache", "n2", "t0", "run_user").unwrap();
        let p = pass(&l, false).unwrap();
        assert_eq!(p.stopped.iter().map(|(r, _)| r.as_str()).collect::<Vec<_>>(), ["run_idle"], "{p:?}");
        assert!(l.revoked_in_chain("run_idle").unwrap().is_some() && l.revoked_in_chain("run_busy").unwrap().is_none());
        assert_eq!(remove(&l, "npm-cache", "alex").unwrap(), 1, "run_busy");
        assert!(l.revoked_in_chain("run_busy").unwrap().is_some());
        assert!(l.services().unwrap().is_empty());
        let kinds: Vec<String> = l.audit_tail(20).unwrap().into_iter().map(|a| a.2).collect();
        assert!(kinds.iter().filter(|k| *k == "service.instance_stopped").count() == 2 && kinds.contains(&"service.removed".to_string()));
        assert!(remove(&l, "npm-cache", "alex").is_err(), "no such service");
        // drain: keep isn't there yet: refused at add.
        std::fs::write(
            &path,
            "task: c\nprogram: { name: npm-cache, command: [x] }\nservice: { port: 4873, drain: keep }\nzone: { name: npm-cache }\n",
        )
        .unwrap();
        assert!(snapshot(&path, &root.join("data")).unwrap_err().to_string().contains("drain: keep"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_snapshot_is_the_service_as_installed_whatever_happens_to_its_files() {
        let root = std::env::temp_dir().join(format!("wicket-svc-snap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("checkout");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("config.yaml"), "publish: $nobody\n").unwrap();
        let manifest = src.join("manifest.yaml");
        std::fs::write(
            &manifest,
            "task: cache\nprogram: { name: npm-cache, command: [x], source: . }\nservice: { port: 4873 }\nzone: { name: npm-cache }\n",
        )
        .unwrap();
        let data = root.join("data");
        let s = snapshot(&manifest, &data).unwrap();
        assert!(s.path.starts_with(data.join("services/npm-cache")), "{}", s.path.display());
        let p = s.manifest.program.as_ref().unwrap();
        assert_eq!(p.source.as_deref(), Some("source"));
        assert!(p.digest.as_deref().unwrap().starts_with("sha256:"), "the source's digest is pinned");
        assert_eq!(std::fs::read_to_string(s.path.parent().unwrap().join("source/config.yaml")).unwrap(), "publish: $nobody\n");
        // Edits to the checkout change nothing installed.
        std::fs::write(src.join("config.yaml"), "publish: $all\n").unwrap();
        assert_eq!(std::fs::read_to_string(s.path.parent().unwrap().join("source/config.yaml")).unwrap(), "publish: $nobody\n");
        // A tampered snapshot isn't loaded.
        let l = Ledger::open_in_memory().unwrap();
        l.add_service("npm-cache", &s.path.display().to_string(), &s.sha256, "t0", "alex").unwrap();
        assert_eq!(installed(&l).unwrap().len(), 1);
        let text = std::fs::read_to_string(&s.path).unwrap();
        std::fs::write(&s.path, text.replace("4873", "4874")).unwrap();
        assert!(installed(&l).unwrap().is_empty(), "its sha256 no longer matches");
        // Refused: a symlink in the source, and a service that may ask for more.
        std::os::unix::fs::symlink("/etc/passwd", src.join("link")).unwrap();
        assert!(snapshot(&manifest, &data).unwrap_err().to_string().contains("copying its source"));
        std::fs::remove_file(src.join("link")).unwrap();
        std::fs::write(
            &manifest,
            "task: c\nprogram: { name: npm-cache, command: [x] }\nservice: { port: 1 }\nzone: { name: z, escalation: { request: true } }\n",
        )
        .unwrap();
        assert!(snapshot(&manifest, &data).unwrap_err().to_string().contains("escalation.request"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
