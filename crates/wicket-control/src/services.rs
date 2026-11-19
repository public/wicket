//! Keeping per-node services running (#579 step 3), each reconcile pass: one instance of each
//! installed service on each node whose boxes use it, per tenant (or one shared, when the service
//! says `tenancy: shared`), started if missing and again (after [`RESTART_AFTER_SECS`]) when it
//! exits. An instance is an ordinary run of the service's program, owned by wicket, on that node.
//! Users reach it through links (`zone.uses`), with its reach (see `wicket_core::service`).

use crate::data_dir;
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use wicket_core::service::{ServiceSpec, Tenancy};
use wicket_store::Ledger;

/// How long after an instance started another may be started for the same service, node and
/// tenant: a service that keeps failing is retried at this pace.
pub const RESTART_AFTER_SECS: i64 = 60;

/// A node as the service loop sees it.
#[derive(Clone, Debug, Default)]
pub struct NodeView {
    pub name: String,
    pub active: bool,
    pub labels: BTreeMap<String, String>,
}

/// An instance to start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Start {
    pub service: String,
    pub node: String,
    pub tenant: String,
}

/// What to start, given the installed services, what live runs want (service, node, tenant), the
/// nodes, and each (service, node, tenant)'s instances (newest first). Pure: the pass's decision.
pub fn plan(
    services: &BTreeMap<String, ServiceSpec>,
    demand: &[(String, String, String)],
    nodes: &[NodeView],
    instances: &dyn Fn(&str, &str, &str) -> Vec<wicket_store::Instance>,
    now: i64,
) -> Vec<Start> {
    let mut out: Vec<Start> = vec![];
    for (service, node, tenant) in demand {
        let Some(spec) = services.get(service) else { continue };
        let Some(n) = nodes.iter().find(|n| &n.name == node && n.active) else { continue };
        if !spec.node_selector.iter().all(|(k, v)| n.labels.get(k) == Some(v)) {
            continue;
        }
        let tenant = match spec.tenancy {
            Tenancy::Shared => wicket_store::SHARED_TENANT.to_string(),
            Tenancy::PerTenant => tenant.clone(),
        };
        let have = instances(service, node, &tenant);
        if have.iter().any(|i| i.live) || have.first().is_some_and(|i| now - i.started_at < RESTART_AFTER_SECS) {
            continue;
        }
        let s = Start { service: service.clone(), node: node.clone(), tenant };
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

/// One pass: what [`plan`] says, started. Returns (what was started, its run) and failures.
pub fn pass(l: &Ledger, dry_run: bool) -> Result<Vec<(Start, String)>> {
    let mut specs = BTreeMap::new();
    let mut paths = BTreeMap::new();
    for s in l.services()? {
        match wicket_core::Manifest::from_yaml(&std::fs::read_to_string(&s.manifest).unwrap_or_default()) {
            Ok(m) if m.service.is_some() => {
                specs.insert(s.name.clone(), m.service.expect("checked"));
                paths.insert(s.name.clone(), s.manifest.clone());
            }
            Ok(_) | Err(_) => say_err!("[wicket] service {}: its manifest {} doesn't load as a service", s.name, s.manifest),
        }
    }
    let nodes: Vec<NodeView> = l
        .nodes()?
        .into_iter()
        .map(|n| NodeView { active: n.status == "active", labels: l.node_labels(&n.name).unwrap_or_default(), name: n.name })
        .collect();
    let demand = l.service_demand()?;
    let starts = plan(&specs, &demand, &nodes, &|s, n, t| l.service_instances(s, n, t).unwrap_or_default(), wicket_store::now());
    let mut done = vec![];
    for s in starts {
        if dry_run {
            done.push((s, String::new()));
            continue;
        }
        let run = wicket_core::RunId::new();
        l.record_service_instance(&run.0, &s.service, &s.node, &s.tenant, wicket_store::now())?;
        start(&paths[&s.service], &s, &run.0).with_context(|| format!("starting service {} on {}", s.service, s.node))?;
        done.push((s, run.0));
    }
    Ok(done)
}

/// Starts an instance: `wicket run --node <node> --run-id <run> <manifest>`, detached, its output
/// in `services/<name>/<run>.log` under the data directory.
fn start(manifest: &str, s: &Start, run: &str) -> Result<()> {
    let dir = data_dir().join("services").join(&s.service);
    std::fs::create_dir_all(&dir)?;
    let log = std::fs::OpenOptions::new().create(true).append(true).open(dir.join(format!("{run}.log")))?;
    let exe = wicket_node::reexec::self_exe()?;
    let mut c = std::process::Command::new(exe);
    c.args(["run", "--node", &s.node, "--run-id", run, manifest]).stdin(std::process::Stdio::null());
    c.stdout(log.try_clone()?);
    c.stderr(log);
    wicket_node::reexec::detach(&mut c);
    c.spawn().context("spawning wicket run")?;
    Ok(())
}

/// The installed service named `name`, its manifest loaded.
fn installed(l: &Ledger, name: &str) -> Option<ServiceSpec> {
    let row = l.services().ok()?.into_iter().find(|s| s.name == name)?;
    wicket_core::Manifest::from_yaml(&std::fs::read_to_string(&row.manifest).ok()?).ok()?.service
}

/// The environment a box whose zone uses `uses` gets from them (each service's `env`, `{host}` and
/// `{port}` filled in), at its start. A service not installed gives nothing (its link says why).
pub fn user_env(l: &Ledger, uses: &[String]) -> Vec<(String, String)> {
    uses.iter().filter_map(|u| installed(l, u).map(|s| s.user_env(u))).flat_map(|e| e.into_iter()).collect()
}

/// How long a box that uses a service waits for its node's instance to run and link (a reconcile
/// pass starts it within 30 s, and its start takes a few more).
pub const LINK_WAIT_SECS: u64 = 120;

/// After a box started (#579 step 3):
/// - a per-node service's instance exposes its port, under its name, to the boxes that use it;
/// - a box whose zone uses services records that (so the reconciler keeps an instance on its node)
///   and is linked to each one's instance there once it runs, as `<name>.wicket.internal`.
pub fn after_start(ctx: &wicket_proxy::RunCtx, m: &wicket_core::Manifest, node: &str) {
    if let (Some(s), Some(p)) = (&m.service, &m.program) {
        let l = ctx.ledger.lock().expect("ledger");
        let zone = serde_json::to_string(&m.zone).unwrap_or_default();
        let exposed = l.expose(&ctx.tenant, &ctx.run.0, s.port, Some(&p.name), &zone).and_then(|_| {
            l.audit(&ctx.tenant, Some(&ctx.run), "link.expose", &serde_json::json!({ "port": s.port, "name": p.name, "service": true }))
        });
        match exposed {
            Ok(_) => say!("[wicket] service {} offers port {} on node {node} to the boxes there that use it", p.name, s.port),
            Err(e) => say_err!("[wicket] service {}: could not expose port {}: {e}", p.name, s.port),
        }
    }
    if m.zone.uses.is_empty() {
        return;
    }
    let tenant = ctx.tenant.0.clone();
    for u in &m.zone.uses {
        let l = ctx.ledger.lock().expect("ledger");
        if let Err(e) = l.want_service(u, node, &tenant, &ctx.run.0) {
            say_err!("[wicket] could not record that this box uses {u}: {e}");
        }
        let Some(spec) = installed(&l, u) else {
            say!("[wicket] this box's zone uses {u}, which isn't installed (wicket service add): not linked");
            continue;
        };
        drop(l);
        let (ctx, u, node) = (ctx.clone(), u.clone(), node.to_string());
        tokio::spawn(async move {
            let t0 = std::time::Instant::now();
            loop {
                let (text, err) = wicket_gateway::link::use_service(&ctx, &u, spec.port).await;
                let waiting = err && (text.contains("no instance") || text.contains("hasn't exposed") || text.contains("not running"));
                if !waiting || t0.elapsed().as_secs() >= LINK_WAIT_SECS {
                    say!("[wicket] {u} on node {node}: {text}");
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicket_store::Instance;

    fn spec(y: &str) -> ServiceSpec {
        wicket_core::yaml::from_str(y).unwrap()
    }

    fn inst(started_at: i64, live: bool) -> Instance {
        Instance { run: "run_i".into(), service: "s".into(), node: "n".into(), tenant: "t".into(), started_at, live }
    }

    /// The example (examples/services/npm-cache) is a valid service: per tenant, read-only reach of
    /// the public registry, and the env that points npm at it.
    #[test]
    fn the_npm_cache_example_is_a_per_tenant_service() {
        let y = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/services/npm-cache/manifest.yaml")).unwrap();
        let m = wicket_core::Manifest::from_yaml(&y).unwrap();
        let s = m.service.as_ref().unwrap();
        assert_eq!((s.port, s.tenancy, s.public_only), (4873, Tenancy::PerTenant, false));
        assert_eq!(s.user_env("npm-cache")["npm_config_registry"], "http://npm-cache.wicket.internal:4873/");
        assert_eq!(m.program.as_ref().unwrap().name, "npm-cache");
        assert!(m.zone.reach.iter().all(|r| r.host == "registry.npmjs.org" && r.methods.iter().all(|x| x == "GET" || x == "HEAD")));
    }

    #[test]
    fn a_box_gets_the_environment_of_the_installed_services_it_uses() {
        let dir = std::env::temp_dir().join(format!("wicket-svc-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("npm-cache.yaml");
        std::fs::write(
            &path,
            concat!(
                "task: cache\nprogram: { name: npm-cache, command: [verdaccio] }\n",
                "service: { port: 4873, env: { npm_config_registry: 'http://{host}:{port}/' } }\n",
                "zone: { name: npm-cache }\n"
            ),
        )
        .unwrap();
        let l = Ledger::open_in_memory().unwrap();
        l.add_service("npm-cache", &path.display().to_string(), "alex").unwrap();
        let uses = vec!["npm-cache".to_string(), "not-installed".to_string()];
        assert_eq!(user_env(&l, &uses), vec![("npm_config_registry".to_string(), "http://npm-cache.wicket.internal:4873/".to_string())]);
        assert!(user_env(&l, &[]).is_empty());
        std::fs::remove_file(&path).unwrap();
        assert!(user_env(&l, &uses).is_empty(), "a manifest gone: nothing");
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn one_instance_per_service_node_and_tenant_that_something_wants() {
        let services = BTreeMap::from([
            ("npm-cache".to_string(), spec("port: 4873")),
            ("oci-mirror".to_string(), spec("port: 5000\ntenancy: shared\npublic_only: true\nnode_selector: { pool: build }")),
        ]);
        let nodes = vec![
            NodeView { name: "n1".into(), active: true, labels: BTreeMap::from([("pool".into(), "build".into())]) },
            NodeView { name: "n2".into(), active: true, ..Default::default() },
            NodeView { name: "gone".into(), active: false, ..Default::default() },
        ];
        let d = |s: &str, n: &str, t: &str| (s.to_string(), n.to_string(), t.to_string());
        let demand = vec![
            d("npm-cache", "n1", "t0"),
            d("npm-cache", "n1", "t1"),
            d("npm-cache", "gone", "t0"),
            d("oci-mirror", "n1", "t0"),
            d("oci-mirror", "n1", "t1"),
            d("oci-mirror", "n2", "t0"),
            d("not-installed", "n1", "t0"),
        ];
        let none = |_: &str, _: &str, _: &str| vec![];
        let got = plan(&services, &demand, &nodes, &none, 1000);
        let s = |s: &str, n: &str, t: &str| Start { service: s.into(), node: n.into(), tenant: t.into() };
        assert_eq!(
            got,
            vec![s("npm-cache", "n1", "t0"), s("npm-cache", "n1", "t1"), s("oci-mirror", "n1", "*")],
            "per tenant by default; shared once per node; only on active nodes its selector matches"
        );
        // A live instance is kept; one that exited is started again only after RESTART_AFTER_SECS.
        let live = |_: &str, _: &str, _: &str| vec![inst(990, true)];
        assert!(plan(&services, &demand[..1], &nodes, &live, 1000).is_empty());
        let just_failed = |_: &str, _: &str, _: &str| vec![inst(990, false)];
        assert!(plan(&services, &demand[..1], &nodes, &just_failed, 1000).is_empty(), "backoff");
        assert_eq!(plan(&services, &demand[..1], &nodes, &just_failed, 990 + RESTART_AFTER_SECS).len(), 1);
    }
}
