//! The static backend: a fixed list of the operator's own machines, reached over ssh. Placement is
//! picking a host with room; a "node" is an allocation of part of a host. Nothing costs money, so the
//! approver is never asked.
//!
//! Allocations live in memory, or, with [`StaticHosts::persistent`], in a JSON file re-read on every
//! call, so a reconciler in another process (or after a restart) sees the same allocations and their
//! tags, as it would see a cloud account's instances. Releasing an allocation destroys nothing (the
//! boxes on a host are the reconciler's business, by Docker label); it only frees the room.

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
    state: Option<std::path::PathBuf>,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Allocs {
    next: u64,
    by_id: BTreeMap<String, NodeHandle>,
}

impl StaticHosts {
    pub fn new(hosts: Vec<StaticHost>) -> StaticHosts {
        StaticHosts { hosts, allocs: Mutex::default(), state: None }
    }

    /// Allocations kept in `state` (JSON, written atomically), shared by every process that opens it.
    /// Callers serialise their changes (the reconciler holds a lock while it acquires and releases).
    pub fn persistent(hosts: Vec<StaticHost>, state: std::path::PathBuf) -> StaticHosts {
        StaticHosts { hosts, allocs: Mutex::default(), state: Some(state) }
    }

    /// Runs `f` on the allocations: the file's, if persistent (written back if `f` changed them).
    fn with<T>(&self, write: bool, f: impl FnOnce(&mut Allocs) -> anyhow::Result<T>) -> anyhow::Result<T> {
        let mut a = self.allocs.lock().expect("allocs");
        if let Some(p) = &self.state {
            *a = match std::fs::read(p) {
                Ok(b) => serde_json::from_slice(&b).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Allocs::default(),
                Err(e) => return Err(e.into()),
            };
        }
        let r = f(&mut a)?;
        if let (Some(p), true) = (&self.state, write) {
            let tmp = p.with_extension("tmp");
            std::fs::write(&tmp, serde_json::to_vec_pretty(&*a)?)?;
            std::fs::rename(&tmp, p)?;
        }
        Ok(r)
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
        self.with(false, |a| {
            Ok(self
                .hosts
                .iter()
                .filter(|h| req.resources.fits_in(&Self::free(a, h)))
                .map(|h| Offer {
                    plan: h.name.clone(),
                    region: h.region.clone(),
                    resources: req.resources,
                    isolation: h.isolation,
                    billing: BillingModel::Free,
                })
                .collect())
        })
    }

    async fn create(&self, spec: &CreateSpec) -> anyhow::Result<NodeHandle> {
        let h =
            self.hosts.iter().find(|h| h.name == spec.offer.plan).ok_or_else(|| anyhow::anyhow!("no static host {}", spec.offer.plan))?;
        self.with(true, |a| {
        if !spec.offer.resources.fits_in(&Self::free(a, h)) {
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
        })
    }

    async fn get(&self, id: &NodeId) -> anyhow::Result<Option<NodeHandle>> {
        self.with(false, |a| Ok(a.by_id.get(&id.0).cloned()))
    }

    async fn list_tagged(&self, tag: &str) -> anyhow::Result<Vec<NodeHandle>> {
        self.with(false, |a| Ok(a.by_id.values().filter(|n| n.has_tag(tag)).cloned().collect()))
    }

    async fn destroy(&self, id: &NodeId) -> anyhow::Result<()> {
        self.with(true, |a| {
            a.by_id.remove(&id.0);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> StaticHost {
        StaticHost {
            name: "n1".into(),
            ssh_target: "wicket@203.0.113.7".into(),
            capacity: Resources { vcpus: 2, memory_mib: 4096 },
            isolation: IsolationTier::Gvisor,
            region: None,
        }
    }

    #[tokio::test]
    async fn persistent_allocations_are_seen_by_another_instance_and_freed_by_it() {
        let dir = std::env::temp_dir().join(format!("wicket-static-{}", ulid::Ulid::new()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("static.json");
        let a = StaticHosts::persistent(vec![host()], path.clone());
        let offer = Offer {
            plan: "n1".into(),
            region: None,
            resources: Resources { vcpus: 2, memory_mib: 1024 },
            isolation: IsolationTier::Gvisor,
            billing: BillingModel::Free,
        };
        let n = a.create(&CreateSpec { offer, name: "x".into(), tags: vec!["wicket-owner-t".into()], boot: None }).await.unwrap();
        // A second process (or the same one after a restart) sees the allocation by tag, and that the
        // host is full.
        let b = StaticHosts::persistent(vec![host()], path.clone());
        assert_eq!(b.list_tagged("wicket-owner-t").await.unwrap(), vec![n.clone()]);
        let req = CapacityRequest {
            resources: Resources { vcpus: 1, memory_mib: 512 },
            min_isolation: IsolationTier::Process,
            region_hint: None,
            plan_hint: None,
            max_hourly: None,
            lifetime_secs: 60,
            idempotency_key: "k".into(),
            name: "y".into(),
            purpose: "test".into(),
            boot: None,
        };
        assert!(b.offers(&req).await.unwrap().is_empty());
        b.destroy(&n.id).await.unwrap();
        assert!(a.get(&n.id).await.unwrap().is_none());
        assert_eq!(a.offers(&req).await.unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
