//! The reconcile plan: what to change in a zone so that the records wicket owns are the ones it
//! wants, and nothing else changes.
//!
//! Inputs:
//! - the wanted box names ([`Desired`]), each with its records, from the ledger's live names;
//! - the zone's records, as the provider listed them;
//! - the records the ledger says this installation created ([`Owned`]).
//!
//! A record is owned only if the ledger lists it and the zone holds an owner record for its box
//! name that the ledger lists too and that names this installation ([`Owned::owns`]). Then, per box
//! name:
//!
//! - **Wanted, and nothing at it that wicket doesn't own:** the owner record, then the wanted
//!   records, are created or updated, and owned records not wanted are deleted.
//! - **Wanted, with a record wicket doesn't own** (someone else's record, an owner record of another
//!   installation, or one of wicket's own the ledger doesn't list): a [`Conflict`]. Nothing at the
//!   name is changed, and it is never adopted.
//! - **Not wanted:** its owned records are deleted, the owner record last. Records it doesn't own
//!   are left.
//!
//! So a plan never updates or deletes a record wicket doesn't own, and never creates one at a name
//! where one is (`props.rs` checks this over random zones).
//!
//! The caller records the plan's new records as owned before applying it ([`Owned::before_apply`]),
//! so a crash mid-apply leaves records the ledger knows of, and forgets the deleted ones after
//! ([`Owned::after_apply`]).

use crate::record::{norm_name, OwnerId, Record, RecordType, Zone};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// One wanted box name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Desired {
    /// The full name, one label under the zone's apex.
    pub name: String,
    /// The grant that holds it, named in its owner record.
    pub grant: String,
    /// Its records (A, AAAA, SRV), each belonging to `name` ([`Record::base`]). The owner record is
    /// added by the plan.
    pub records: Vec<Record>,
    /// The owner record's TTL.
    pub ttl: u32,
}

/// The records the ledger lists as created by this installation, by identity ([`Record::key`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Owned {
    keys: BTreeSet<(String, RecordType, String)>,
}

impl Owned {
    pub fn new<'a>(records: impl IntoIterator<Item = &'a Record>) -> Owned {
        Owned { keys: records.into_iter().map(|r| r.normalized().key()).collect() }
    }

    pub fn lists(&self, r: &Record) -> bool {
        self.keys.contains(&r.key())
    }

    /// The box names whose owner record in `zone_records` is listed and names `owner`.
    fn our_bases(&self, owner: &OwnerId, zone_records: &[Record]) -> BTreeSet<String> {
        zone_records
            .iter()
            .filter(|r| r.is_owner_record() && owner.is_owner_of(&r.value) && self.lists(r))
            .map(|r| r.base().to_string())
            .collect()
    }

    /// Whether `r`, one of `zone_records` (normalized), is this installation's: listed here, and
    /// its box name's owner record in the zone is listed here and names `owner`. An owner record
    /// itself must name `owner`.
    pub fn owns(&self, owner: &OwnerId, zone_records: &[Record], r: &Record) -> bool {
        self.owns_in(&self.our_bases(owner, zone_records), owner, r)
    }

    fn owns_in(&self, our_bases: &BTreeSet<String>, owner: &OwnerId, r: &Record) -> bool {
        self.lists(r) && our_bases.contains(r.base()) && (!r.is_owner_record() || owner.is_owner_of(&r.value))
    }

    /// The ledger's list once a plan's new records are recorded: before it is applied.
    pub fn before_apply(&self, plan: &Plan) -> Owned {
        let mut o = self.clone();
        for c in &plan.changes {
            match c {
                Change::Create(r) | Change::Update { to: r, .. } => {
                    o.keys.insert(r.key());
                }
                Change::Delete(_) => {}
            }
        }
        o
    }

    /// The ledger's list once a plan has been applied: its new records recorded, the records it
    /// deleted or replaced forgotten.
    pub fn after_apply(&self, plan: &Plan) -> Owned {
        let mut o = self.clone();
        for c in &plan.changes {
            if let Change::Delete(r) | Change::Update { from: r, .. } = c {
                o.keys.remove(&r.key());
            }
        }
        // After the removals: a value one change replaced and another wrote stays listed.
        o.before_apply(plan)
    }
}

/// One change to a zone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase", tag = "op")]
pub enum Change {
    Create(Record),
    /// The same name and type, another value or TTL.
    Update {
        from: Record,
        to: Record,
    },
    Delete(Record),
}

/// A wanted name the zone has records at that wicket doesn't own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Conflict {
    pub name: String,
    /// The records there wicket doesn't own.
    pub records: Vec<Record>,
}

/// The changes, in the order they are to be applied, and the names left alone as conflicts.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub changes: Vec<Change>,
    pub conflicts: Vec<Conflict>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Applies the changes to a list of records, in order. Fails, changing nothing, if a record
    /// to update or delete isn't there.
    pub fn apply_to(&self, records: &mut Vec<Record>) -> Result<(), String> {
        let mut out = records.clone();
        for c in &self.changes {
            match c {
                Change::Create(r) => out.push(r.clone()),
                Change::Update { from, to } => {
                    let i = out
                        .iter()
                        .position(|x| x == from)
                        .ok_or_else(|| format!("no {} {} {:?} to update", from.name, from.rtype, from.value))?;
                    out[i] = to.clone();
                }
                Change::Delete(r) => {
                    let i = out.iter().position(|x| x == r).ok_or_else(|| format!("no {} {} {:?} to delete", r.name, r.rtype, r.value))?;
                    out.remove(i);
                }
            }
        }
        *records = out;
        Ok(())
    }
}

/// A wanted name the plan can't be made for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// Not one label under the zone's apex.
    OutsideZone(String),
    /// Wanted twice.
    Duplicate(String),
    /// A record that doesn't belong to its wanted name, or of a type wicket doesn't write there.
    BadRecord { name: String, record: String },
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlanError::OutsideZone(n) => write!(f, "{n} isn't a name one label under the zone"),
            PlanError::Duplicate(n) => write!(f, "{n} is wanted twice"),
            PlanError::BadRecord { name, record } => write!(f, "{record} isn't a record wicket writes for {name}"),
        }
    }
}

impl std::error::Error for PlanError {}

/// The plan for `zone` (see the module's documentation).
pub fn plan(zone: &Zone, owner: &OwnerId, desired: &[Desired], zone_records: &[Record], owned: &Owned) -> Result<Plan, PlanError> {
    // What is wanted, per box name, the owner record included.
    let mut want: BTreeMap<String, Vec<Record>> = BTreeMap::new();
    for d in desired {
        let name = norm_name(&d.name);
        if !zone.holds_box_name(&name) {
            return Err(PlanError::OutsideZone(name));
        }
        if want.contains_key(&name) {
            return Err(PlanError::Duplicate(name));
        }
        let mut recs = vec![owner.owner_record(&name, &d.grant, d.ttl)];
        for r in &d.records {
            let r = r.normalized();
            let ok = r.base() == name && matches!(r.rtype, RecordType::A | RecordType::Aaaa | RecordType::Srv);
            if !ok {
                return Err(PlanError::BadRecord { name, record: format!("{} {} {:?}", r.name, r.rtype, r.value) });
            }
            if !recs.iter().any(|x| x.key() == r.key()) {
                recs.push(r);
            }
        }
        want.insert(name, recs);
    }

    let mut have: Vec<Record> = zone_records.iter().map(Record::normalized).collect();
    // One record per identity: an RRset has one TTL, so a listing can't hold two.
    have.sort();
    have.dedup_by(|a, b| a.key() == b.key());
    let our_bases = owned.our_bases(owner, &have);
    let mut at: BTreeMap<String, (Vec<Record>, Vec<Record>)> = BTreeMap::new(); // (owned, not owned)
    for r in &have {
        let e = at.entry(r.base().to_string()).or_default();
        if owned.owns_in(&our_bases, owner, r) {
            e.0.push(r.clone());
        } else {
            e.1.push(r.clone());
        }
    }

    let mut out = Plan::default();
    let bases: BTreeSet<String> =
        want.keys().cloned().chain(at.iter().filter(|(_, (o, _))| !o.is_empty()).map(|(b, _)| b.clone())).collect();
    for base in bases {
        let (mine, theirs) = at.remove(&base).unwrap_or_default();
        match want.get(&base) {
            Some(_) if !theirs.is_empty() => out.conflicts.push(Conflict { name: base, records: theirs }),
            Some(w) => out.changes.extend(converge(&mine, w)),
            None => {
                // Not wanted: its records, the owner record last.
                let (owner_recs, data): (Vec<_>, Vec<_>) = mine.into_iter().partition(Record::is_owner_record);
                out.changes.extend(data.into_iter().map(Change::Delete));
                out.changes.extend(owner_recs.into_iter().map(Change::Delete));
            }
        }
    }
    Ok(out)
}

/// The changes that turn `have` (all owned, at one name) into `want`: the owner record's change
/// first, then the rest, grouped by record name and type.
fn converge(have: &[Record], want: &[Record]) -> Vec<Change> {
    // Keyed (not the owner record, name, type): the owner record's group sorts first. Each holds
    // (have, want).
    type Group = (Vec<Record>, Vec<Record>);
    let mut groups: BTreeMap<(bool, String, RecordType), Group> = BTreeMap::new();
    for r in have {
        groups.entry((!r.is_owner_record(), r.name.clone(), r.rtype)).or_default().0.push(r.clone());
    }
    for r in want {
        groups.entry((!r.is_owner_record(), r.name.clone(), r.rtype)).or_default().1.push(r.clone());
    }
    let mut changes = Vec::new();
    for (_, (h, w)) in groups {
        let mut olds = Vec::new();
        let mut news = Vec::new();
        for x in &w {
            match h.iter().find(|y| y.key() == x.key()) {
                Some(y) if y.ttl == x.ttl => {}
                Some(y) => changes.push(Change::Update { from: y.clone(), to: x.clone() }),
                None => news.push(x.clone()),
            }
        }
        for y in &h {
            if !w.iter().any(|x| x.key() == y.key()) {
                olds.push(y.clone());
            }
        }
        let paired = olds.len().min(news.len());
        let mut olds = olds.into_iter();
        let mut news = news.into_iter();
        for _ in 0..paired {
            changes.push(Change::Update { from: olds.next().expect("paired"), to: news.next().expect("paired") });
        }
        changes.extend(news.map(Change::Create));
        changes.extend(olds.map(Change::Delete));
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn setup() -> (Zone, OwnerId) {
        (Zone::new("boxes.example.com"), OwnerId::parse("ourowner1").unwrap())
    }

    fn demo(ip: [u8; 4], port: u16) -> Desired {
        let n = "demo.boxes.example.com";
        Desired {
            name: n.into(),
            grant: "g1".into(),
            records: vec![Record::a(n, Ipv4Addr::from(ip), 60), Record::srv(n, "http", port, 60)],
            ttl: 60,
        }
    }

    #[test]
    fn a_new_name_gets_its_owner_record_first() {
        let (z, o) = setup();
        let p = plan(&z, &o, &[demo([192, 0, 2, 1], 20001)], &[], &Owned::default()).unwrap();
        assert_eq!(p.changes.len(), 3);
        assert!(matches!(&p.changes[0], Change::Create(r) if r.is_owner_record()));
        assert!(p.conflicts.is_empty());
    }

    #[test]
    fn a_move_is_an_update_and_an_end_deletes_the_owner_record_last() {
        let (z, o) = setup();
        let d = demo([192, 0, 2, 1], 20001);
        let p = plan(&z, &o, std::slice::from_ref(&d), &[], &Owned::default()).unwrap();
        let mut zone = vec![];
        p.apply_to(&mut zone).unwrap();
        let owned = Owned::default().after_apply(&p);

        let moved = demo([198, 51, 100, 7], 20001);
        let p2 = plan(&z, &o, &[moved], &zone, &owned).unwrap();
        assert_eq!(p2.changes.len(), 1, "{p2:?}");
        assert!(matches!(&p2.changes[0], Change::Update { from, to } if from.value == "192.0.2.1" && to.value == "198.51.100.7"));

        let p3 = plan(&z, &o, &[], &zone, &owned).unwrap();
        assert_eq!(p3.changes.len(), 3);
        assert!(matches!(p3.changes.last(), Some(Change::Delete(r)) if r.is_owner_record()));
    }

    #[test]
    fn someone_elses_record_is_a_conflict_and_is_left() {
        let (z, o) = setup();
        let theirs = Record::a("demo.boxes.example.com", Ipv4Addr::new(203, 0, 113, 9), 300);
        let p = plan(&z, &o, &[demo([192, 0, 2, 1], 20001)], std::slice::from_ref(&theirs), &Owned::default()).unwrap();
        assert!(p.changes.is_empty());
        assert_eq!(p.conflicts, vec![Conflict { name: "demo.boxes.example.com".into(), records: vec![theirs.clone()] }]);
        // Listed in the ledger but without our owner record in the zone: still not ours.
        let p = plan(&z, &o, &[], std::slice::from_ref(&theirs), &Owned::new([&theirs])).unwrap();
        assert!(p.is_empty());
    }

    #[test]
    fn wanted_names_are_checked() {
        let (z, o) = setup();
        let mut d = demo([192, 0, 2, 1], 1);
        d.name = "a.demo.boxes.example.com".into();
        assert!(matches!(plan(&z, &o, &[d], &[], &Owned::default()), Err(PlanError::OutsideZone(_))));
        let mut d = demo([192, 0, 2, 1], 1);
        d.records.push(Record::txt("demo.boxes.example.com", "x", 60));
        assert!(matches!(plan(&z, &o, &[d], &[], &Owned::default()), Err(PlanError::BadRecord { .. })));
        let d = demo([192, 0, 2, 1], 1);
        assert!(matches!(plan(&z, &o, &[d.clone(), d], &[], &Owned::default()), Err(PlanError::Duplicate(_))));
    }
}
