//! The DNS provider trait, and the providers that need no DNS service: [`NoopProvider`], chosen by
//! an installation's config, and [`MemoryProvider`], for tests and the simulation.
//!
//! A provider only lists and applies. The plan is wicket's ([`crate::plan`]), so what wicket may
//! change doesn't depend on a provider getting ownership right. A provider runs on the control host,
//! in the reconciler, with its credential from the vault; nodes never hold one.

use crate::plan::{Change, Plan};
use crate::record::{Record, RecordType, Zone};
use std::future::Future;
use std::sync::Mutex;

/// What a provider supports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caps {
    pub types: Vec<RecordType>,
    /// The lowest TTL it accepts.
    pub min_ttl: u32,
    /// Whether `apply` makes all of a plan's changes or none.
    pub atomic: bool,
}

impl Caps {
    /// Refuses a plan with a record type or TTL the provider doesn't take.
    pub fn check(&self, plan: &Plan) -> Result<(), ProviderError> {
        for c in &plan.changes {
            let r = match c {
                Change::Create(r) | Change::Update { to: r, .. } | Change::Delete(r) => r,
            };
            if !self.types.contains(&r.rtype) {
                return Err(ProviderError::Unsupported(format!("{} records", r.rtype)));
            }
            if !matches!(c, Change::Delete(_)) && r.ttl < self.min_ttl {
                return Err(ProviderError::Unsupported(format!("a TTL of {} s (at least {})", r.ttl, self.min_ttl)));
            }
        }
        Ok(())
    }
}

/// What `apply` did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    /// False for a provider that only reports (the no-op one).
    pub applied: bool,
    pub changes: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProviderError {
    #[error("the provider doesn't support {0}")]
    Unsupported(String),
    #[error("the provider doesn't serve zone {0}")]
    Zone(String),
    #[error("the provider refused the change: {0}")]
    Failed(String),
    /// A provider whose apply isn't atomic made the plan's first `done` changes, in order, and
    /// then stopped: the caller records those as made (#748, F8).
    #[error("the provider made {done} of the plan's changes, then stopped: {why}")]
    Partial { done: usize, why: String },
}

/// A DNS provider: one implementation per DNS service (Vultr, RFC 2136, …).
pub trait DnsProvider: Send + Sync {
    /// Its name in the config (`names.public.provider`).
    fn id(&self) -> &str;
    fn caps(&self) -> Caps;
    /// Whether `apply` changes the zone. False for a provider that only reports (the no-op one):
    /// the reconciler then records nothing as created, so the ledger never claims a record that
    /// isn't there.
    fn writes(&self) -> bool {
        true
    }
    /// Every record in the zone.
    fn list(&self, zone: &Zone) -> impl Future<Output = Result<Vec<Record>, ProviderError>> + Send;
    /// Applies a plan wicket computed, in its order.
    fn apply(&self, zone: &Zone, plan: &Plan) -> impl Future<Output = Result<Applied, ProviderError>> + Send;
}

/// The no-op provider: it lists an empty zone, applies nothing, and keeps each plan it was given,
/// so an operator sees what wicket would do before giving it a credential.
#[derive(Debug, Default)]
pub struct NoopProvider {
    plans: Mutex<Vec<Plan>>,
}

impl NoopProvider {
    pub fn new() -> NoopProvider {
        NoopProvider::default()
    }

    /// The plans given to `apply`, oldest first.
    pub fn plans(&self) -> Vec<Plan> {
        self.plans.lock().expect("plans").clone()
    }
}

impl DnsProvider for NoopProvider {
    fn id(&self) -> &str {
        "noop"
    }

    fn writes(&self) -> bool {
        false
    }

    fn caps(&self) -> Caps {
        Caps { types: vec![RecordType::A, RecordType::Aaaa, RecordType::Srv, RecordType::Txt], min_ttl: 1, atomic: true }
    }

    async fn list(&self, _zone: &Zone) -> Result<Vec<Record>, ProviderError> {
        Ok(Vec::new())
    }

    async fn apply(&self, _zone: &Zone, plan: &Plan) -> Result<Applied, ProviderError> {
        self.caps().check(plan)?;
        self.plans.lock().expect("plans").push(plan.clone());
        Ok(Applied { applied: false, changes: plan.changes.len() })
    }
}

/// A zone in memory, applied atomically: for tests and the simulation.
#[derive(Debug)]
pub struct MemoryProvider {
    zone: Zone,
    records: Mutex<Vec<Record>>,
}

impl MemoryProvider {
    pub fn new(zone: Zone, records: Vec<Record>) -> MemoryProvider {
        MemoryProvider { zone, records: Mutex::new(records) }
    }

    pub fn records(&self) -> Vec<Record> {
        self.records.lock().expect("records").clone()
    }

    fn serves(&self, zone: &Zone) -> Result<(), ProviderError> {
        if zone == &self.zone {
            Ok(())
        } else {
            Err(ProviderError::Zone(zone.apex().to_string()))
        }
    }
}

impl DnsProvider for MemoryProvider {
    fn id(&self) -> &str {
        "memory"
    }

    fn caps(&self) -> Caps {
        Caps { types: vec![RecordType::A, RecordType::Aaaa, RecordType::Srv, RecordType::Txt, RecordType::Other], min_ttl: 1, atomic: true }
    }

    async fn list(&self, zone: &Zone) -> Result<Vec<Record>, ProviderError> {
        self.serves(zone)?;
        Ok(self.records())
    }

    async fn apply(&self, zone: &Zone, plan: &Plan) -> Result<Applied, ProviderError> {
        self.serves(zone)?;
        self.caps().check(plan)?;
        let mut g = self.records.lock().expect("records");
        plan.apply_to(&mut g).map_err(ProviderError::Failed)?;
        Ok(Applied { applied: true, changes: plan.changes.len() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{plan, Desired, Owned};
    use crate::record::OwnerId;
    use std::net::Ipv4Addr;

    fn wanted() -> (Zone, OwnerId, Desired) {
        let z = Zone::new("boxes.example.com");
        let n = z.name("demo");
        let d = Desired { name: n.clone(), grant: "g1".into(), records: vec![Record::a(&n, Ipv4Addr::new(192, 0, 2, 1), 60)], ttl: 60 };
        (z, OwnerId::parse("ourowner1").unwrap(), d)
    }

    #[tokio::test]
    async fn noop_reports_and_changes_nothing() {
        let (z, o, d) = wanted();
        let p = NoopProvider::new();
        let listed = p.list(&z).await.unwrap();
        let pl = plan(&z, &o, &[d], &listed, &Owned::default()).unwrap();
        let a = p.apply(&z, &pl).await.unwrap();
        assert_eq!(a, Applied { applied: false, changes: 2 });
        assert_eq!(p.plans(), vec![pl]);
        assert!(p.list(&z).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn memory_applies_and_converges() {
        let (z, o, d) = wanted();
        let theirs = Record::a(&z.name("www"), Ipv4Addr::new(203, 0, 113, 1), 300);
        let p = MemoryProvider::new(z.clone(), vec![theirs.clone()]);
        let pl = plan(&z, &o, std::slice::from_ref(&d), &p.list(&z).await.unwrap(), &Owned::default()).unwrap();
        let owned = Owned::default().before_apply(&pl);
        p.apply(&z, &pl).await.unwrap();
        let owned = owned.after_apply(&pl);
        assert!(p.records().contains(&theirs));
        let again = plan(&z, &o, &[d], &p.list(&z).await.unwrap(), &owned).unwrap();
        assert!(again.is_empty(), "{again:?}");
        assert_eq!(p.list(&Zone::new("other.example.com")).await, Err(ProviderError::Zone("other.example.com".into())));
    }

    #[test]
    fn caps_refuse_what_a_provider_lacks() {
        let (z, o, d) = wanted();
        let pl = plan(&z, &o, &[d], &[], &Owned::default()).unwrap();
        let c = Caps { types: vec![RecordType::A], min_ttl: 1, atomic: false };
        assert_eq!(c.check(&pl), Err(ProviderError::Unsupported("TXT records".into())));
        let c = Caps { types: vec![RecordType::A, RecordType::Txt], min_ttl: 300, atomic: false };
        assert!(matches!(c.check(&pl), Err(ProviderError::Unsupported(_))));
    }
}
