//! Properties of the reconcile plan (#575), over seeded random zones, ledgers and wanted names:
//!
//! 1. Every record a plan updates or deletes is in the zone and owned ([`Owned::owns`]): listed in
//!    the ledger, with this installation's listed owner record at its name.
//! 2. Every record a plan creates or writes belongs to a wanted name, and the zone has no record at
//!    that name wicket doesn't own.
//! 3. After the plan is applied, every record wicket doesn't own is still there, unchanged; a
//!    wanted name without conflict has exactly its wanted records; a conflicted one is untouched;
//!    a name no longer wanted has none of wicket's records left.
//! 4. The owner record is written before a name's other records, and deleted after them.
//! 5. Planning again, with the ledger updated, changes nothing.
//!
//! No property-testing crate: a small seeded generator, as wicket-store's `props.rs`, so a failure
//! names its seed.

use crate::plan::{plan, Change, Desired, Owned, Plan};
use crate::record::{OwnerId, Record, RecordType, Zone};
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// xorshift64*: enough to drive the cases, and reproducible from its seed.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.below(100) < pct
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }
}

const LABELS: &[&str] = &["a", "b", "c", "d", "e", "f"];
const OURS: &str = "ourowner1";
const THEIRS: &str = "theirowner2";
const GRANTS: &[&str] = &["g1", "g2"];
const TTLS: &[u32] = &[60, 300];

struct World {
    zone: Zone,
    owner: OwnerId,
    records: Vec<Record>,
    owned: Owned,
    /// The ledger's list, kept apart from `owned` for the model's own ownership test.
    listed: BTreeSet<(String, RecordType, String)>,
    desired: Vec<Desired>,
}

fn data_record(rng: &mut Rng, name: &str) -> Record {
    let ttl = *rng.pick(TTLS);
    match rng.below(3) {
        0 => Record::a(name, Ipv4Addr::new(192, 0, 2, 1 + rng.below(3) as u8), ttl),
        1 => Record::aaaa(name, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1 + rng.below(3) as u16), ttl),
        _ => Record::srv(name, "http", 20000 + rng.below(3) as u16, ttl),
    }
}

/// A zone with a mix of: wicket's records (listed or not, with its owner record or without), another
/// installation's, a human's (A records, CNAMEs, TXT at the apex), and stale ledger entries.
fn world(seed: u64) -> World {
    let mut rng = Rng::new(seed);
    let zone = Zone::new("boxes.example.com");
    let ours = OwnerId::parse(OURS).unwrap();
    let theirs = OwnerId::parse(THEIRS).unwrap();
    let mut records = Vec::new();
    let mut listed = Vec::new();
    for l in LABELS {
        let name = zone.name(l);
        match rng.below(6) {
            0 => {} // nothing there
            1 | 2 => {
                // wicket's: its owner record (listed, mostly), and some records (listed, mostly)
                let o = ours.owner_record(&name, rng.pick(GRANTS), *rng.pick(TTLS));
                if rng.chance(85) {
                    listed.push(o.clone());
                }
                records.push(o);
                for _ in 0..rng.below(4) {
                    let r = data_record(&mut rng, &name);
                    if rng.chance(85) {
                        listed.push(r.clone());
                    }
                    records.push(r);
                }
            }
            3 => {
                // another installation's, sometimes listed in this ledger by mistake
                let o = theirs.owner_record(&name, "gx", 60);
                let r = data_record(&mut rng, &name);
                if rng.chance(30) {
                    listed.push(o.clone());
                    listed.push(r.clone());
                }
                records.extend([o, r]);
            }
            4 => {
                // a human's record, maybe next to wicket's owner record
                let r = if rng.chance(50) {
                    Record::a(&name, Ipv4Addr::new(203, 0, 113, 5), 3600)
                } else {
                    Record { name: name.clone(), rtype: RecordType::Other, value: "elsewhere.example.net".into(), ttl: 3600 }
                };
                if rng.chance(30) {
                    listed.push(r.clone());
                }
                records.push(r);
                if rng.chance(50) {
                    let o = ours.owner_record(&name, "g1", 60);
                    listed.push(o.clone());
                    records.push(o);
                }
            }
            _ => {
                // only in the ledger: created and lost, or never applied
                listed.push(data_record(&mut rng, &name));
                listed.push(ours.owner_record(&name, "g1", 60));
            }
        }
    }
    // Records at the apex and below a box name, never wicket's.
    records.push(Record::txt(zone.apex(), "v=spf1 -all", 3600));
    records.push(Record::txt(&format!("_dmarc.{}", zone.apex()), "v=DMARC1; p=reject", 3600));
    records.push(Record::a(&format!("x.{}", zone.name("a")), Ipv4Addr::new(203, 0, 113, 6), 3600));
    if rng.chance(40) {
        // Another owner's record beside ours, listed by this ledger by mistake half the time.
        let name = zone.name(rng.pick(LABELS));
        let stray = theirs.owner_record(&name, "gy", 60);
        if rng.chance(50) {
            listed.push(stray.clone());
        }
        records.push(stray);
    }
    let mut desired = Vec::new();
    for l in LABELS {
        if rng.chance(50) {
            let name = zone.name(l);
            let records = (0..1 + rng.below(3)).map(|_| data_record(&mut rng, &name)).collect();
            desired.push(Desired { name, grant: rng.pick(GRANTS).to_string(), records, ttl: *rng.pick(TTLS) });
        }
    }
    let listed_keys = listed.iter().map(Record::key).collect();
    World { zone, owner: ours, owned: Owned::new(&listed), listed: listed_keys, records: dedup(records), desired }
}

/// The zone as a DNS server holds it: one record per identity.
fn dedup(mut rs: Vec<Record>) -> Vec<Record> {
    let mut seen = BTreeSet::new();
    rs.retain(|r| seen.insert(r.key()));
    rs
}

fn at<'a>(rs: &'a [Record], base: &str) -> BTreeSet<&'a Record> {
    rs.iter().filter(|r| r.base() == base).collect()
}

/// The model's ownership, written apart from [`Owned::owns`]: the ledger lists the record, and the
/// zone holds a TXT at `_wicket.<its box name>` that the ledger lists and that begins with this
/// installation's owner field.
fn model_owns(w: &World, r: &Record) -> bool {
    let mut base = r.name.as_str();
    while base.starts_with('_') && base.contains('.') {
        base = &base[base.find('.').unwrap() + 1..];
    }
    let owner_name = format!("_wicket.{base}");
    let ours = |t: &Record| {
        t.rtype == RecordType::Txt
            && t.name == owner_name
            && t.value.starts_with(&format!("wicket-owner={OURS};"))
            && w.listed.contains(&t.key())
    };
    let is_owner = r.rtype == RecordType::Txt && r.name == owner_name;
    w.listed.contains(&r.key()) && w.records.iter().any(ours) && (!is_owner || ours(r))
}

fn wanted(w: &World, d: &Desired) -> BTreeSet<Record> {
    // One record per identity, the first of a duplicate winning, as in `plan`; and the owner record.
    let mut seen = BTreeSet::new();
    let mut s: BTreeSet<Record> = d.records.iter().filter(|r| seen.insert(r.key())).cloned().collect();
    s.insert(w.owner.owner_record(&d.name, &d.grant, d.ttl));
    s
}

fn check(seed: u64) {
    let w = world(seed);
    let p = plan(&w.zone, &w.owner, &w.desired, &w.records, &w.owned).unwrap_or_else(|e| panic!("seed {seed}: {e}"));
    let owns = |r: &Record| model_owns(&w, r);
    for r in &w.records {
        assert_eq!(w.owned.owns(&w.owner, &w.records, r), owns(r), "seed {seed}: Owned::owns and the model differ on {r:?}");
    }
    let wanted_names: BTreeSet<&str> = w.desired.iter().map(|d| d.name.as_str()).collect();
    let conflicted: BTreeSet<&str> = p.conflicts.iter().map(|c| c.name.as_str()).collect();

    // 1 and 2.
    for c in &p.changes {
        match c {
            Change::Delete(r) | Change::Update { from: r, .. } => {
                assert!(w.records.contains(r), "seed {seed}: {c:?} changes a record the zone doesn't have");
                assert!(owns(r), "seed {seed}: {c:?} changes a record wicket doesn't own");
            }
            Change::Create(_) => {}
        }
        if let Change::Create(r) | Change::Update { to: r, .. } = c {
            assert!(wanted_names.contains(r.base()), "seed {seed}: {c:?} writes at a name not wanted");
            assert!(!conflicted.contains(r.base()), "seed {seed}: {c:?} writes at a conflicted name");
            assert!(at(&w.records, r.base()).iter().all(|x| owns(x)), "seed {seed}: {c:?} writes next to a record wicket doesn't own");
        }
    }

    // 3.
    let mut after = w.records.clone();
    p.apply_to(&mut after).unwrap_or_else(|e| panic!("seed {seed}: {e}"));
    for r in w.records.iter().filter(|r| !owns(r)) {
        assert!(after.contains(r), "seed {seed}: {r:?}, not wicket's, is gone or changed");
    }
    for d in &w.desired {
        let now: BTreeSet<Record> = at(&after, &d.name).into_iter().cloned().collect();
        if conflicted.contains(d.name.as_str()) {
            let before: BTreeSet<Record> = at(&w.records, &d.name).into_iter().cloned().collect();
            assert_eq!(now, before, "seed {seed}: conflicted {} changed", d.name);
            assert!(before.iter().any(|r| !owns(r)), "seed {seed}: {} is a conflict with only wicket's records", d.name);
        } else {
            assert_eq!(now, wanted(&w, d), "seed {seed}: {} isn't as wanted", d.name);
        }
    }
    let bases: BTreeSet<&str> = w.records.iter().map(|r| r.base()).collect();
    for b in bases.into_iter().filter(|b| !wanted_names.contains(b)) {
        let left: Vec<_> = at(&after, b).into_iter().filter(|r| owns(r)).collect();
        assert!(left.is_empty(), "seed {seed}: {b} isn't wanted but keeps {left:?}");
    }

    // 4.
    order(seed, &p);

    // 5.
    let owned = w.owned.before_apply(&p).after_apply(&p);
    let again = plan(&w.zone, &w.owner, &w.desired, &after, &owned).unwrap();
    assert!(again.is_empty(), "seed {seed}: a second plan changes {:?}", again.changes);
    let again_conflicts: BTreeSet<&str> = again.conflicts.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(again_conflicts, conflicted, "seed {seed}: the conflicts changed");
}

fn order(seed: u64, p: &Plan) {
    let target = |c: &Change| match c {
        Change::Create(r) | Change::Update { to: r, .. } | Change::Delete(r) => r.clone(),
    };
    for (i, c) in p.changes.iter().enumerate() {
        let r = target(c);
        if r.is_owner_record() {
            continue;
        }
        let owner_change = p.changes.iter().position(|x| target(x).is_owner_record() && target(x).base() == r.base());
        match (c, owner_change) {
            (Change::Delete(_), Some(j)) if matches!(p.changes[j], Change::Delete(_)) => {
                assert!(j > i, "seed {seed}: the owner record of {} goes before its records", r.base())
            }
            (Change::Create(_) | Change::Update { .. }, Some(j)) => {
                assert!(j < i, "seed {seed}: {} is written before its owner record", r.name)
            }
            _ => {}
        }
    }
}

#[test]
fn plans_never_touch_records_wicket_does_not_own() {
    for seed in 0..5000 {
        check(seed);
    }
}

/// The generator reaches every case the properties are about.
#[test]
fn the_generator_covers_the_cases() {
    let (mut conflicts, mut creates, mut updates, mut deletes, mut left) = (0, 0, 0, 0, 0);
    for seed in 0..5000 {
        let w = world(seed);
        let p = plan(&w.zone, &w.owner, &w.desired, &w.records, &w.owned).unwrap();
        conflicts += p.conflicts.len();
        for c in &p.changes {
            match c {
                Change::Create(_) => creates += 1,
                Change::Update { .. } => updates += 1,
                Change::Delete(_) => deletes += 1,
            }
        }
        left += w.records.iter().filter(|r| w.owned.lists(r) && !model_owns(&w, r)).count();
    }
    for (what, n) in
        [("conflicts", conflicts), ("creates", creates), ("updates", updates), ("deletes", deletes), ("listed but not owned", left)]
    {
        assert!(n > 100, "only {n} {what}");
    }
}
