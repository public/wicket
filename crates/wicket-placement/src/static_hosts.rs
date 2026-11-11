//! The static backend: a fixed list of the operator's own machines, reached over ssh. Placement is
//! picking a host with room; a "node" is an allocation of part of a host. Nothing costs money, so the
//! approver is never asked.
//!
//! Allocations live in memory: after a restart, the hosts are all free again. That is safe because
//! releasing an allocation destroys nothing (the boxes on a host are the reaper's and the reconciler's
//! business, by Docker label).

use crate::billing::BillingModel;
use crate::model::*;
use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Clone, Debug, PartialEq, serde::Deserialize)]
pub struct StaticHost {
    /// Its name: an enrolled node's name, so `wicket run --node <name>` reaches it pinned.
    pub name: String,
    /// `user@address` for ssh.
    pub ssh_target: String,
    /// What wicket may use of it.
    pub capacity: Resources,
    /// The strongest tier it supports (gVisor on a VPS, vm with KVM).
    pub isolation: IsolationTier,
    #[serde(default)]
    pub region: Option<String>,
}

pub struct StaticHosts {
    hosts: Vec<StaticHost>,
    allocs: Mutex<Allocs>,
}

#[derive(Default)]
struct Allocs {
    next: u64,
    by_id: BTreeMap<String, NodeHandle>,
}

impl StaticHosts {
    pub fn new(hosts: Vec<StaticHost>) -> StaticHosts {
        StaticHosts { hosts, allocs: Mutex::default() }
    }

    fn used(a: &Allocs, host: &str) -> Resources {
        a.by_id.values().filter(|n| n.plan.as_deref() == Some(host)).fold(Resources::default(), |u, n| Resources {
            vcpus: u.vcpus + n.resources.vcpus,
            memory_mib: u.memory_mib + n.resources.memory_mib,
        })
    }

    fn free(a: &Allocs, h: &StaticHost) -> Resources {
        let u = Self::used(a, &h.name);
        Resources { vcpus: h.capacity.vcpus.saturating_sub(u.vcpus), memory_mib: h.capacity.memory_mib.saturating_sub(u.memory_mib) }
    }
}

impl Provider for StaticHosts {
    fn id(&self) -> &str {
        "static"
    }

    /// One offer per host with room for the request, sized to the request (a host is shared).
    async fn offers(&self, req: &CapacityRequest) -> anyhow::Result<Vec<Offer>> {
        let a = self.allocs.lock().expect("allocs");
        Ok(self
            .hosts
            .iter()
            .filter(|h| req.resources.fits_in(&Self::free(&a, h)))
            .map(|h| Offer {
                plan: h.name.clone(),
                region: h.region.clone(),
                resources: req.resources,
                isolation: h.isolation,
                billing: BillingModel::Free,
            })
            .collect())
    }

    async fn create(&self, spec: &CreateSpec) -> anyhow::Result<NodeHandle> {
        let h =
            self.hosts.iter().find(|h| h.name == spec.offer.plan).ok_or_else(|| anyhow::anyhow!("no static host {}", spec.offer.plan))?;
        let mut a = self.allocs.lock().expect("allocs");
        if !spec.offer.resources.fits_in(&Self::free(&a, h)) {
            anyhow::bail!("host {} no longer has room", h.name);
        }
        a.next += 1;
        let id = format!("{}#{}", h.name, a.next);
        let n = NodeHandle {
            id: NodeId(id.clone()),
            backend: "static".into(),
            name: h.name.clone(),
            ssh_target: Some(h.ssh_target.clone()),
            region: h.region.clone(),
            plan: Some(h.name.clone()),
            isolation: h.isolation,
            resources: spec.offer.resources,
            billing: BillingModel::Free,
            created_at: now(),
            lease_until: Owner::lease_from_tags(&spec.tags),
            host_key: None,
            tags: spec.tags.clone(),
            state: NodeState::Active,
        };
        a.by_id.insert(id, n.clone());
        Ok(n)
    }

    async fn get(&self, id: &NodeId) -> anyhow::Result<Option<NodeHandle>> {
        Ok(self.allocs.lock().expect("allocs").by_id.get(&id.0).cloned())
    }

    async fn list_tagged(&self, tag: &str) -> anyhow::Result<Vec<NodeHandle>> {
        Ok(self.allocs.lock().expect("allocs").by_id.values().filter(|n| n.has_tag(tag)).cloned().collect())
    }

    async fn destroy(&self, id: &NodeId) -> anyhow::Result<()> {
        self.allocs.lock().expect("allocs").by_id.remove(&id.0);
        Ok(())
    }
}
