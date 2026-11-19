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
