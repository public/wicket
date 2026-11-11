//! The placement rules, on a fake backend: the money envelope, approval, idempotency, owner tags,
//! release before the next paid hour, and the static-host backend.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use wicket_placement::billing::BillingModel;
use wicket_placement::envelope::{DenyAll, EnvelopeRefusal};
use wicket_placement::model::PROTECTED_TAG;
use wicket_placement::static_hosts::{StaticHost, StaticHosts};
use wicket_placement::*;

const H: i64 = 3600;

/// A provider with fixed offers and an in-memory account (shared, so a second Placer sees the same
/// account, as after a restart).
#[derive(Clone, Default)]
struct Fake {
    offers: Vec<Offer>,
    account: Arc<Mutex<Account>>,
    clock: Arc<AtomicI64>,
}

#[derive(Default)]
struct Account {
    nodes: BTreeMap<String, NodeHandle>,
    creates: usize,
    destroys: Vec<String>,
}

fn offer(plan: &str, vcpus: u32, mib: u64, micro_per_hour: u64) -> Offer {
    Offer {
        plan: plan.into(),
        region: Some("lhr".into()),
        resources: Resources { vcpus, memory_mib: mib },
        isolation: IsolationTier::Gvisor,
        billing: BillingModel::vultr(MicroUsd(micro_per_hour)),
    }
}

impl Fake {
    fn new(offers: Vec<Offer>) -> Fake {
        Fake { offers, ..Default::default() }
    }

    fn creates(&self) -> usize {
        self.account.lock().unwrap().creates
    }

    /// Adds a node created outside this placer (another installation, the control host, …).
    fn insert(&self, id: &str, tags: Vec<String>, created: i64) {
        let n = NodeHandle {
            id: NodeId(id.into()),
            backend: "fake".into(),
            name: id.into(),
            ssh_target: Some("wicket@203.0.113.10".into()),
            region: Some("lhr".into()),
            plan: Some("small".into()),
            isolation: IsolationTier::Gvisor,
            resources: Resources { vcpus: 1, memory_mib: 1024 },
            billing: BillingModel::vultr(MicroUsd(10_000)),
            created_at: created,
            lease_until: wicket_placement::model::Owner::lease_from_tags(&tags),
            host_key: None,
            tags,
            state: NodeState::Active,
        };
        self.account.lock().unwrap().nodes.insert(id.into(), n);
    }
}

impl Provider for Fake {
    fn id(&self) -> &str {
        "fake"
    }
    async fn offers(&self, _req: &CapacityRequest) -> anyhow::Result<Vec<Offer>> {
        Ok(self.offers.clone())
    }
    async fn create(&self, spec: &CreateSpec) -> anyhow::Result<NodeHandle> {
        let mut a = self.account.lock().unwrap();
        a.creates += 1;
        let id = format!("i-{}", a.creates);
        let n = NodeHandle {
            id: NodeId(id.clone()),
            backend: "fake".into(),
            name: spec.name.clone(),
            ssh_target: Some(format!("wicket@203.0.113.{}", a.creates)),
            region: spec.offer.region.clone(),
            plan: Some(spec.offer.plan.clone()),
            isolation: spec.offer.isolation,
            resources: spec.offer.resources,
            billing: spec.offer.billing,
            created_at: self.clock.load(Ordering::SeqCst),
            lease_until: Owner::lease_from_tags(&spec.tags),
            host_key: None,
            tags: spec.tags.clone(),
            state: NodeState::Active,
        };
        a.nodes.insert(id, n.clone());
        Ok(n)
    }
    async fn get(&self, id: &NodeId) -> anyhow::Result<Option<NodeHandle>> {
        Ok(self.account.lock().unwrap().nodes.get(&id.0).cloned())
    }
    async fn list_tagged(&self, tag: &str) -> anyhow::Result<Vec<NodeHandle>> {
        Ok(self.account.lock().unwrap().nodes.values().filter(|n| n.has_tag(tag)).cloned().collect())
    }
    async fn destroy(&self, id: &NodeId) -> anyhow::Result<()> {
        let mut a = self.account.lock().unwrap();
        a.nodes.remove(&id.0);
        a.destroys.push(id.0.clone());
        Ok(())
    }
}

/// Approves or denies, and records what it was asked.
#[derive(Clone)]
struct Human {
    yes: bool,
    asked: Arc<Mutex<Vec<SpendRequest>>>,
}

impl Human {
    fn new(yes: bool) -> Human {
        Human { yes, asked: Arc::default() }
    }
    fn asked(&self) -> Vec<SpendRequest> {
        self.asked.lock().unwrap().clone()
    }
}

impl SpendApprover for Human {
    async fn approve(&self, req: &SpendRequest) -> Approval {
        self.asked.lock().unwrap().push(req.clone());
        if self.yes {
            Approval::Approved
        } else {
            Approval::Denied("the operator said no".into())
        }
    }
}

fn envelope(hourly: &str, total: &str) -> MoneyEnvelope {
    MoneyEnvelope { max_hourly: MicroUsd::parse_dollars(hourly).unwrap(), max_total: MicroUsd::parse_dollars(total).unwrap() }
}

fn req(key: &str, lifetime: i64) -> CapacityRequest {
    CapacityRequest {
        resources: Resources { vcpus: 1, memory_mib: 1024 },
        min_isolation: IsolationTier::Gvisor,
        region_hint: Some("lhr".into()),
        plan_hint: None,
        max_hourly: None,
        lifetime_secs: lifetime,
        idempotency_key: key.into(),
        name: "n1".into(),
        purpose: "test".into(),
        boot: None,
    }
}

fn placer(f: &Fake, human: &Human, env: MoneyEnvelope) -> Placer<Fake, Human> {
    let c = f.clock.clone();
    Placer::new(f.clone(), human.clone(), Owner::new("example"), env).with_clock(Arc::new(move || c.load(Ordering::SeqCst)))
}

#[tokio::test]
async fn a_paid_node_needs_a_human_and_carries_the_owner_idempotency_and_lease_tags() {
    let f = Fake::new(vec![offer("big", 4, 8192, 60_000), offer("small", 1, 1024, 14_000)]);
    let human = Human::new(true);
    let p = placer(&f, &human, envelope("0.10", "1.00"));
    let n = p.acquire(&req("task-1", 30 * 60)).await.unwrap();
    // Cheapest offer that fits.
    assert_eq!(n.plan.as_deref(), Some("small"));
    let owner = Owner::new("example");
    assert!(n.has_tag(&owner.tag()));
    assert!(n.has_tag(&owner.idem_tag("task-1")));
    // A 30-minute lease ends at minute 50 of its only hour.
    assert_eq!(n.lease_until, Some(50 * 60));
    let asked = human.asked();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].plan, "small");
    assert_eq!(asked[0].hourly, MicroUsd(14_000));
    assert_eq!(asked[0].worst_case, MicroUsd::from_cents(2)); // one started hour, $0.014 → $0.02
    assert_eq!(p.list().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_denied_request_creates_nothing() {
    let f = Fake::new(vec![offer("small", 1, 1024, 14_000)]);
    let human = Human::new(false);
    let e = placer(&f, &human, envelope("0.10", "1.00")).acquire(&req("k", H)).await.unwrap_err();
    assert!(matches!(e, PlacementError::NotApproved(_)), "{e}");
    assert_eq!(f.creates(), 0);
    // With no approver configured, nothing paid is ever created.
    let e = Placer::new(f.clone(), DenyAll, Owner::new("example"), envelope("0.10", "1.00")).acquire(&req("k", H)).await.unwrap_err();
    assert!(matches!(e, PlacementError::NotApproved(_)));
    assert_eq!(f.creates(), 0);
}

#[tokio::test]
async fn the_envelope_refuses_before_any_human_is_asked() {
    let f = Fake::new(vec![offer("small", 1, 1024, 14_000)]);
    let human = Human::new(true);
    // Hourly: $0.014/h against a $0.01/h cap.
    let e = placer(&f, &human, envelope("0.01", "100")).acquire(&req("a", H)).await.unwrap_err();
    assert!(matches!(e, PlacementError::Envelope(EnvelopeRefusal::Hourly { .. })), "{e}");
    // Total: 11 hours at $0.014 is $0.154, billed $0.16, over $0.15 (10 hours, $0.14, would fit).
    let e = placer(&f, &human, envelope("1", "0.15")).acquire(&req("b", 11 * H)).await.unwrap_err();
    assert!(matches!(e, PlacementError::Envelope(EnvelopeRefusal::Total { .. })), "{e}");
    assert!(human.asked().is_empty());
    assert_eq!(f.creates(), 0);
}

#[tokio::test]
async fn the_envelope_counts_nodes_already_running() {
    let f = Fake::new(vec![offer("small", 1, 1024, 14_000)]);
    let human = Human::new(true);
    let owner = Owner::new("example");
    // Two owned nodes at $0.01/h, leased for 3 hours: $0.02/h and 2 × $0.03 committed.
    f.insert("old-1", vec![owner.tag(), Owner::lease_tag(3 * H - 600)], 0);
    f.insert("old-2", vec![owner.tag(), Owner::lease_tag(3 * H - 600)], 0);
    // Someone else's node doesn't count (and isn't listed).
    f.insert("theirs", vec![Owner::new("other").tag()], 0);
    let e = placer(&f, &human, envelope("0.03", "10")).acquire(&req("a", H)).await.unwrap_err();
    assert!(matches!(e, PlacementError::Envelope(EnvelopeRefusal::Hourly { .. })), "{e}");
    let e = placer(&f, &human, envelope("1", "0.07")).acquire(&req("a", H)).await.unwrap_err();
    assert!(matches!(e, PlacementError::Envelope(EnvelopeRefusal::Total { .. })), "{e}");
    let p = placer(&f, &human, envelope("0.04", "0.09"));
    p.acquire(&req("a", 30 * 60)).await.unwrap();
    assert_eq!(human.asked()[0].committed_hourly, MicroUsd::from_cents(2));
    assert_eq!(human.asked()[0].committed_total, MicroUsd::from_cents(6));
    assert_eq!(p.list().await.unwrap().len(), 3);
}

#[tokio::test]
async fn the_same_idempotency_key_returns_the_same_node_even_after_a_restart() {
    let f = Fake::new(vec![offer("small", 1, 1024, 14_000)]);
    let human = Human::new(true);
    let p = placer(&f, &human, envelope("1", "10"));
    let a = p.acquire(&req("task-7", H)).await.unwrap();
    let b = p.acquire(&req("task-7", H)).await.unwrap();
    assert_eq!(a.id, b.id);
    assert_eq!(f.creates(), 1);
    // A new process (empty memory) finds it at the provider by its tag, without asking again.
    let p2 = placer(&f, &human, envelope("1", "10"));
    assert_eq!(p2.acquire(&req("task-7", H)).await.unwrap().id, a.id);
    assert_eq!(f.creates(), 1);
    assert_eq!(human.asked().len(), 1);
    // Another key is another node.
    assert_ne!(p2.acquire(&req("task-8", H)).await.unwrap().id, a.id);
    assert_eq!(f.creates(), 2);
}

#[tokio::test]
async fn concurrent_acquires_with_one_key_create_once() {
    let f = Fake::new(vec![offer("small", 1, 1024, 14_000)]);
    let human = Human::new(true);
    let p = Arc::new(placer(&f, &human, envelope("1", "10")));
    let (r1, r2) = (req("k", H), req("k", H));
    let (a, b) = tokio::join!(p.acquire(&r1), p.acquire(&r2));
    assert_eq!(a.unwrap().id, b.unwrap().id);
    assert_eq!(f.creates(), 1);
}

#[tokio::test]
async fn release_refuses_unowned_and_protected_nodes() {
    let f = Fake::new(vec![]);
    let human = Human::new(true);
    let owner = Owner::new("example");
    f.insert("control-host", vec![], 0);
    f.insert("theirs", vec![Owner::new("other").tag()], 0);
    f.insert("broker", vec![owner.tag(), PROTECTED_TAG.into()], 0);
    let p = placer(&f, &human, envelope("1", "10"));
    for (id, protected) in [("control-host", false), ("theirs", false), ("broker", true)] {
        let e = p.release(&NodeId(id.into()), ReleaseMode::Now).await.unwrap_err();
        match e {
            PlacementError::Protected(_) => assert!(protected),
            PlacementError::NotOwned(_) => assert!(!protected),
            e => panic!("{e}"),
        }
        // Nor does get show it.
        assert_eq!(p.get(&NodeId(id.into())).await.unwrap().is_some(), protected);
    }
    assert!(f.account.lock().unwrap().destroys.is_empty());
    assert_eq!(p.release(&NodeId("never-existed".into()), ReleaseMode::Now).await.unwrap(), Released::AlreadyGone);
}

#[tokio::test]
async fn release_keeps_a_node_warm_within_its_paid_hour_and_reuses_it() {
    let f = Fake::new(vec![offer("small", 1, 1024, 14_000)]);
    let human = Human::new(true);
    let p = placer(&f, &human, envelope("1", "10"));
    let n = p.acquire(&req("first", 10 * 60)).await.unwrap();
    assert_eq!(p.next_paid_hour_at(&n), Some(H));
    // Done after 15 minutes, more work may come: kept until minute 50, already paid for.
    f.clock.store(15 * 60, Ordering::SeqCst);
    assert_eq!(p.release(&n.id, ReleaseMode::Billing { more_work_expected: true }).await.unwrap(), Released::Pooled { until: 50 * 60 });
    // The next request takes it: no create, no approval.
    f.clock.store(20 * 60, Ordering::SeqCst);
    let m = p.acquire(&req("second", 15 * 60)).await.unwrap();
    assert_eq!(m.id, n.id);
    assert_eq!(f.creates(), 1);
    assert_eq!(human.asked().len(), 1);
    // Released again with too little paid time left to be worth keeping: destroyed.
    f.clock.store(52 * 60, Ordering::SeqCst);
    assert_eq!(p.release(&m.id, ReleaseMode::Billing { more_work_expected: true }).await.unwrap(), Released::Destroyed);
    assert_eq!(f.account.lock().unwrap().destroys, vec![n.id.0.clone()]);
}

#[tokio::test]
async fn a_pooled_node_is_destroyed_before_its_next_paid_hour_and_not_claimed_late() {
    let f = Fake::new(vec![offer("small", 1, 1024, 14_000)]);
    let human = Human::new(true);
    let p = placer(&f, &human, envelope("1", "10"));
    let n = p.acquire(&req("first", 10 * 60)).await.unwrap();
    f.clock.store(5 * 60, Ordering::SeqCst);
    p.release(&n.id, ReleaseMode::Billing { more_work_expected: true }).await.unwrap();
    // 45 minutes in: only 15 paid minutes left, under the 20 a claim needs, so a new node is made.
    f.clock.store(45 * 60, Ordering::SeqCst);
    let m = p.acquire(&req("second", 10 * 60)).await.unwrap();
    assert_ne!(m.id, n.id);
    assert!(p.expire_pool().await.unwrap().is_empty());
    // At minute 50 the pool expires it.
    f.clock.store(50 * 60, Ordering::SeqCst);
    assert_eq!(p.expire_pool().await.unwrap(), vec![n.id.clone()]);
    assert!(p.pooled().await.is_empty());
    // m, released 5 minutes into its first hour, is kept until its minute 50 (95 minutes in our clock);
    // a request for an hour would run past that, so it gets a new node instead.
    assert_eq!(
        p.release(&m.id, ReleaseMode::Billing { more_work_expected: true }).await.unwrap(),
        Released::Pooled { until: 45 * 60 + 50 * 60 }
    );
    let k = p.acquire(&req("third", H)).await.unwrap();
    assert_ne!(k.id, m.id);
    assert_eq!(f.creates(), 3);
    // Released for good, it goes now and leaves the pool.
    assert_eq!(p.release(&m.id, ReleaseMode::Now).await.unwrap(), Released::Destroyed);
    assert!(p.pooled().await.is_empty());
}

#[tokio::test]
async fn offers_are_filtered_by_size_isolation_price_and_ranked_by_preference() {
    let mut vm = offer("kvm", 2, 4096, 100_000);
    vm.isolation = IsolationTier::Vm;
    let mut ams = offer("cheap-ams", 1, 1024, 5_000);
    ams.region = Some("ams".into());
    let f = Fake::new(vec![offer("small", 1, 1024, 14_000), offer("big", 4, 8192, 60_000), vm, ams]);
    let human = Human::new(true);
    let p = placer(&f, &human, envelope("10", "100"));
    // Region preference beats price.
    assert_eq!(p.acquire(&req("a", H)).await.unwrap().plan.as_deref(), Some("small"));
    // A plan hint beats both.
    let mut r = req("b", H);
    r.plan_hint = Some("big".into());
    assert_eq!(p.acquire(&r).await.unwrap().plan.as_deref(), Some("big"));
    // Only the KVM offer satisfies vm.
    let mut r = req("c", H);
    r.min_isolation = IsolationTier::Vm;
    assert_eq!(p.acquire(&r).await.unwrap().plan.as_deref(), Some("kvm"));
    // Too big for anything, or over the request's own price limit: no capacity, nothing asked.
    let asked = human.asked().len();
    let mut r = req("d", H);
    r.resources.memory_mib = 1 << 20;
    assert!(matches!(p.acquire(&r).await.unwrap_err(), PlacementError::NoCapacity(_)));
    let mut r = req("e", H);
    r.resources.vcpus = 2;
    r.max_hourly = MicroUsd::parse_dollars("0.05");
    assert!(matches!(p.acquire(&r).await.unwrap_err(), PlacementError::NoCapacity(_)));
    assert_eq!(human.asked().len(), asked);
}

#[tokio::test]
async fn static_hosts_place_by_free_capacity_without_spending() {
    let hosts = vec![
        StaticHost {
            name: "mini".into(),
            ssh_target: "wicket@203.0.113.20".into(),
            capacity: Resources { vcpus: 2, memory_mib: 2048 },
            isolation: IsolationTier::Gvisor,
            region: None,
        },
        StaticHost {
            name: "kvm-box".into(),
            ssh_target: "wicket@203.0.113.21".into(),
            capacity: Resources { vcpus: 8, memory_mib: 16384 },
            isolation: IsolationTier::Vm,
            region: None,
        },
    ];
    // DenyAll: the static backend never spends, so it never asks.
    let p = Placer::new(StaticHosts::new(hosts), DenyAll, Owner::new("example"), envelope("0", "0"));
    let mut r = req("a", H);
    r.region_hint = None;
    r.resources = Resources { vcpus: 2, memory_mib: 2048 };
    let a = p.acquire(&r).await.unwrap();
    assert_eq!(a.ssh_target.as_deref(), Some("wicket@203.0.113.20"));
    assert_eq!(a.billing, BillingModel::Free);
    assert!(a.has_tag(&Owner::new("example").tag()));
    assert_eq!(p.next_paid_hour_at(&a), None);
    // mini is full now; the next one lands on kvm-box.
    let b = p.acquire(&CapacityRequest { idempotency_key: "b".into(), ..r.clone() }).await.unwrap();
    assert_eq!(b.name, "kvm-box");
    // A vm zone goes only to kvm-box; too big for what's left: no capacity.
    let mut big = CapacityRequest { idempotency_key: "c".into(), ..r.clone() };
    big.resources = Resources { vcpus: 7, memory_mib: 1024 };
    assert!(matches!(p.acquire(&big).await.unwrap_err(), PlacementError::NoCapacity(_)));
    // Free billing: release frees at once, whatever the mode, and mini takes work again.
    assert_eq!(p.release(&a.id, ReleaseMode::Billing { more_work_expected: true }).await.unwrap(), Released::Destroyed);
    let c = p.acquire(&CapacityRequest { idempotency_key: "d".into(), ..r.clone() }).await.unwrap();
    assert_eq!(c.name, "mini");
    assert_eq!(p.list().await.unwrap().len(), 2);
}
