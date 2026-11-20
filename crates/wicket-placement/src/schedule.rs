//! Which node a box goes on (#579): filter the nodes it may go on, then score them.
//!
//! A pure function of what the control host knows when it decides: each node's room as it reported
//! it (`NodeCapacity`, #377), its labels and taints, and whether its CA covers the box's inspected
//! hosts or may be widened to them (#573). The node's own admission stays the last word: a node may
//! still refuse a box this picked, and then nothing was reserved.
//!
//! **Filter:** a node is out if it starts no box now (`full`), hasn't the vCPUs or memory the box's
//! limits ask for, lacks a label the box's `node_selector` names (or has another value), has a
//! taint the box doesn't tolerate, or has a CA that doesn't cover the box's hosts and may not be
//! widened to them. Each node that is out says every reason why.
//!
//! A node is also out if it lacks something the box requires near it (a service's instance, a
//! volume), or runs a box the box requires to be away from (another zone's, or one principal's).
//!
//! **Score:** of the nodes left, first the most preferences met (each preferred affinity it has,
//! each preferred anti-affinity it doesn't break), then bin-pack (the default: the one left with
//! the least memory, then the fewest vCPUs, once the box is on it, so the fewest nodes are kept busy)
//! or spread (the most). Ties go to `last` (where the box ran before), then to the name, so the same
//! inputs always give the same node.
//!
//! **Queue** ([`queue_order`]): runs waiting for a node are served first come, first served across
//! tenants; within a tenant, its own runs fill its places in line by priority, highest first.
//!
//! **Preemption** ([`preempt`]): when no node may take a box, which boxes to stop to make room: only
//! those whose manifest marks them preemptible and whose priority is below the box's, the fewest on
//! one node, of the lowest priority. It decides; stopping them is the caller's, through the normal
//! stop, and the node's admission still decides the start that follows.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use wicket_core::placement::{Affinity, AntiAffinity, Away, Near, Taint};

/// What a box asks for: its limits, as requests, and its placement constraints.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Request {
    pub vcpus: f32,
    pub memory_mib: u64,
    pub node_selector: BTreeMap<String, String>,
    pub tolerations: Vec<Taint>,
    /// Where it waits, and which boxes it may displace (#579 step 4). Absent from a request recorded
    /// before step 4: 0.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub priority: i32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub preemptible: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affinity: Vec<Affinity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub anti_affinity: Vec<AntiAffinity>,
    /// The node protocol its record needs (#664: a zone that decides an encoded slash needs 19); 0:
    /// any. The caller sets it: placement doesn't know the node protocol's versions.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub min_protocol: u32,
}

fn is_zero(n: &i32) -> bool {
    *n == 0
}

fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl Request {
    pub fn of(m: &wicket_core::Manifest) -> Request {
        Request {
            vcpus: m.zone.limits.cpus,
            memory_mib: m.zone.limits.memory_bytes().unwrap_or(0) >> 20,
            node_selector: m.placement.node_selector.clone(),
            tolerations: m.placement.tolerations(),
            priority: m.placement.priority,
            preemptible: m.placement.preemptible,
            affinity: m.placement.affinity.clone(),
            anti_affinity: m.placement.anti_affinity.clone(),
            min_protocol: 0,
        }
    }

    /// How many of its preferences `node` meets: each preferred affinity it has, each preferred
    /// anti-affinity it doesn't break.
    pub fn preferences_met(&self, node: &Node) -> usize {
        let near = self.affinity.iter().filter(|a| !a.required).filter_map(Affinity::near).filter(|n| node.has(n)).count();
        let away = self.anti_affinity.iter().filter(|a| !a.required).filter_map(AntiAffinity::away).filter(|a| !node.runs(a)).count();
        near + away
    }
}

/// Whether a node's CA can serve the box's inspected hosts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Coverage {
    /// It covers them all (or the box inspects none).
    #[default]
    Covers,
    /// Not yet, but its policy lets it be widened to these.
    Widens(Vec<String>),
    /// Its policy keeps these out.
    Refuses(Vec<String>),
}

/// A node as the scheduler sees it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Node {
    pub name: String,
    pub vcpus: f32,
    pub used_vcpus: f32,
    pub memory_mib: u64,
    pub used_memory_mib: u64,
    /// The memory limit a new box may have now, by the node's own admission (#377).
    pub room_mib: Option<u64>,
    /// It starts no box now (its disk below the floor).
    pub full: bool,
    pub labels: BTreeMap<String, String>,
    pub taints: Vec<Taint>,
    pub ca: Coverage,
    /// The per-node services whose instance runs on it.
    pub services: BTreeSet<String>,
    /// The volumes it holds.
    pub volumes: BTreeSet<String>,
    /// The zones of the boxes on it, and their principals' ids.
    pub zones: BTreeSet<String>,
    pub principals: BTreeSet<String>,
    /// The protocol it last talked to the control host, if it has connected.
    pub protocol: Option<u32>,
}

impl Node {
    /// Whether it has what an affinity term names.
    pub fn has(&self, near: &Near) -> bool {
        match near {
            Near::Service(s) => self.services.contains(s),
            Near::Volume(v) => self.volumes.contains(v),
        }
    }

    /// Whether it runs a box an anti-affinity term names.
    pub fn runs(&self, away: &Away) -> bool {
        match away {
            Away::Zone(z) => self.zones.contains(z),
            Away::Principal(p) => self.principals.contains(p),
        }
    }

    /// vCPUs and MiB free: what its limits leave, and no more memory than its admission allows.
    pub fn free(&self) -> (f32, i64) {
        let by_limits = self.memory_mib as i64 - self.used_memory_mib as i64;
        (self.vcpus - self.used_vcpus, self.room_mib.map_or(by_limits, |r| by_limits.min(r as i64)))
    }
}

/// Bin-pack (fewest nodes busy) or spread (most room left on each).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Strategy {
    #[default]
    BinPack,
    Spread,
}

/// Why a node is out.
#[derive(Clone, Debug, PartialEq)]
pub enum Refusal {
    Full,
    NoRoom {
        free_vcpus: f32,
        free_mib: i64,
    },
    Label {
        key: String,
        want: String,
        has: Option<String>,
    },
    Taint(Taint),
    Ca(Vec<String>),
    /// It lacks what the box requires near it.
    Near(Near),
    /// It runs a box the box requires to be away from.
    Away(Away),
    /// Its protocol (None: not known yet) is below what the box's record needs.
    Protocol {
        needs: u32,
        has: Option<u32>,
    },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Full => f.write_str("its disk is below the floor"),
            Refusal::NoRoom { free_vcpus, free_mib } => write!(f, "{free_vcpus:.1} vCPU, {free_mib} MiB free"),
            Refusal::Label { key, want, has: None } => write!(f, "no label {key} (wanted {key}={want})"),
            Refusal::Label { key, want, has: Some(h) } => write!(f, "label {key}={h}, not {want}"),
            Refusal::Taint(t) => write!(f, "tainted {t}, not tolerated"),
            Refusal::Ca(h) => write!(f, "its CA doesn't cover {} and its policy keeps them out", h.join(", ")),
            Refusal::Near(n) => write!(f, "no {n} here, which the box requires"),
            Refusal::Away(a) => write!(f, "runs a box of {a}, which the box requires to be away from"),
            Refusal::Protocol { needs, has: Some(h) } => write!(f, "talks protocol {h}, and the box's zone needs {needs}"),
            Refusal::Protocol { needs, has: None } => write!(f, "its protocol isn't known yet, and the box's zone needs {needs}"),
        }
    }
}

/// A decision, and why: the node chosen (if any may take the box), the others it may go on in
/// score order, and the nodes that are out with their reasons.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Decision {
    pub node: Option<String>,
    /// Every node the box may go on, best first (`node` is the first).
    pub ranked: Vec<String>,
    /// The nodes it may not go on, by name, each with every reason.
    pub refused: Vec<(String, Vec<Refusal>)>,
}

impl Decision {
    /// One line per refused node: `n1 (its disk is below the floor), n2 (…; …)`.
    pub fn why_not(&self) -> String {
        self.refused
            .iter()
            .map(|(n, rs)| format!("{n} ({})", rs.iter().map(|r| r.to_string()).collect::<Vec<_>>().join("; ")))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Every reason `node` may not take `req` (none: it may).
pub fn filter(req: &Request, node: &Node) -> Vec<Refusal> {
    let mut out = vec![];
    if node.full {
        out.push(Refusal::Full);
    } else {
        let (cpu, mem) = node.free();
        if cpu + 1e-3 < req.vcpus || mem < req.memory_mib as i64 {
            out.push(Refusal::NoRoom { free_vcpus: cpu, free_mib: mem });
        }
    }
    for (k, want) in &req.node_selector {
        let has = node.labels.get(k);
        if has != Some(want) {
            out.push(Refusal::Label { key: k.clone(), want: want.clone(), has: has.cloned() });
        }
    }
    for t in &node.taints {
        if !req.tolerations.iter().any(|tol| tol.tolerates(t)) {
            out.push(Refusal::Taint(t.clone()));
        }
    }
    if let Coverage::Refuses(h) = &node.ca {
        out.push(Refusal::Ca(h.clone()));
    }
    for n in req.affinity.iter().filter(|a| a.required).filter_map(Affinity::near) {
        if !node.has(&n) {
            out.push(Refusal::Near(n));
        }
    }
    for a in req.anti_affinity.iter().filter(|a| a.required).filter_map(AntiAffinity::away) {
        if node.runs(&a) {
            out.push(Refusal::Away(a));
        }
    }
    if req.min_protocol > 0 && node.protocol.is_none_or(|p| p < req.min_protocol) {
        out.push(Refusal::Protocol { needs: req.min_protocol, has: node.protocol });
    }
    out
}

/// Where `req` goes (see the module's doc).
pub fn schedule(req: &Request, nodes: &[Node], strategy: Strategy, last: Option<&str>) -> Decision {
    let mut ok: Vec<&Node> = vec![];
    let mut refused = vec![];
    for n in nodes {
        let why = filter(req, n);
        if why.is_empty() {
            ok.push(n);
        } else {
            refused.push((n.name.clone(), why));
        }
    }
    let left = |n: &Node| {
        let (cpu, mem) = n.free();
        (mem - req.memory_mib as i64, ((cpu - req.vcpus) * 1000.0).round() as i64)
    };
    ok.sort_by(|a, b| {
        let (la, lb) = (left(a), left(b));
        let by_room = match strategy {
            Strategy::BinPack => la.cmp(&lb),
            Strategy::Spread => lb.cmp(&la),
        };
        let by_preference = req.preferences_met(b).cmp(&req.preferences_met(a));
        by_preference
            .then(by_room)
            .then_with(|| (Some(a.name.as_str()) != last).cmp(&(Some(b.name.as_str()) != last)))
            .then_with(|| a.name.cmp(&b.name))
    });
    refused.sort_by(|a, b| a.0.cmp(&b.0));
    let ranked: Vec<String> = ok.iter().map(|n| n.name.clone()).collect();
    Decision { node: ranked.first().cloned(), ranked, refused }
}

/// A run waiting for a node, as the queue orders it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Waiter {
    pub run: String,
    /// Whose run it is: its priority counts only against its own tenant's runs.
    pub tenant: String,
    pub priority: i32,
    /// When it first waited (ms).
    pub at_ms: i64,
}

/// Within one tenant: the highest priority first, first come, first served within one, then by run.
fn within_tenant(a: &Waiter, b: &Waiter) -> Ordering {
    b.priority.cmp(&a.priority).then(a.at_ms.cmp(&b.at_ms)).then_with(|| a.run.cmp(&b.run))
}

/// The order waiting runs are served in, fair across tenants: each tenant's runs keep the places in
/// line they took (first come, first served across tenants), and priority decides only which of a
/// tenant's own runs fills each of its places. So a priority, which a manifest declares, never moves
/// another tenant's runs. Total and deterministic: a tie between tenants goes to the tenant's name.
pub fn queue_order(waiting: &[Waiter]) -> Vec<&Waiter> {
    let mut by_tenant: BTreeMap<&str, Vec<&Waiter>> = BTreeMap::new();
    for w in waiting {
        by_tenant.entry(w.tenant.as_str()).or_default().push(w);
    }
    // (place, tenant, rank within the tenant): the rank breaks a tie between two of a tenant's places
    // taken at the same time, so its order there is still by priority.
    let mut placed: Vec<(i64, &str, usize, &Waiter)> = vec![];
    for (tenant, mut runs) in by_tenant {
        let mut places: Vec<i64> = runs.iter().map(|w| w.at_ms).collect();
        places.sort_unstable();
        runs.sort_by(|a, b| within_tenant(a, b));
        for (rank, (at, w)) in places.into_iter().zip(runs).enumerate() {
            placed.push((at, tenant, rank, w));
        }
    }
    placed.sort_by(|a, b| (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2)));
    placed.into_iter().map(|(_, _, _, w)| w).collect()
}

/// The waiters served before `me`, in the order they're served (`me` itself, if listed, is not).
pub fn ahead<'a>(me: &Waiter, waiting: &'a [Waiter]) -> Vec<&'a Waiter> {
    let mut all: Vec<Waiter> = waiting.iter().filter(|w| w.run != me.run).cloned().collect();
    all.push(me.clone());
    let order: Vec<String> = queue_order(&all).into_iter().map(|w| w.run.clone()).collect();
    let mine = order.iter().position(|r| r == &me.run).unwrap_or(order.len());
    order[..mine].iter().filter_map(|r| waiting.iter().find(|w| &w.run == r)).collect()
}

/// A box running on a node, as preemption sees it.
#[derive(Clone, Debug, PartialEq)]
pub struct Running {
    pub run: String,
    pub vcpus: f32,
    pub memory_mib: u64,
    pub priority: i32,
    pub preemptible: bool,
}

impl Running {
    /// Whether a box asking `req` may stop it: its manifest marks it preemptible, and it ranks below.
    pub fn yields_to(&self, req: &Request) -> bool {
        self.preemptible && self.priority < req.priority
    }
}

/// What to stop for a box no node may take now: on `node`, the runs `victims` (by run id).
#[derive(Clone, Debug, PartialEq)]
pub struct Preemption {
    pub node: String,
    pub victims: Vec<String>,
    /// The highest priority among them.
    pub max_priority: i32,
}

/// `node` with `gone`'s boxes stopped: their vCPUs and memory free, and as much more room by its
/// admission.
fn without(node: &Node, gone: &[&Running]) -> Node {
    let cpu: f32 = gone.iter().map(|r| r.vcpus).sum();
    let mib: u64 = gone.iter().map(|r| r.memory_mib).sum();
    Node {
        used_vcpus: (node.used_vcpus - cpu).max(0.0),
        used_memory_mib: node.used_memory_mib.saturating_sub(mib),
        room_mib: node.room_mib.map(|r| r.saturating_add(mib)),
        ..node.clone()
    }
}

/// Which boxes to stop so `req` may go on a node (see the module's doc), or None: a node may take it
/// already, or stopping every box it may stop on a node still leaves no room there.
///
/// Only room is made: a node that is out for any other reason (its disk, a label, a taint, its CA,
/// an affinity) stays out. On each node the boxes it may stop are taken lowest priority first (then
/// the most memory, then the most vCPUs, then by run id) until it fits, and then any it fits without
/// is put back, so every one chosen is needed (no victim can be kept; not necessarily the fewest
/// boxes that would make room). Of the nodes it can be made to fit on, the one whose
/// highest-priority victim is lowest, then with the fewest victims, then by name.
pub fn preempt(req: &Request, nodes: &[Node], running: &BTreeMap<String, Vec<Running>>, strategy: Strategy) -> Option<Preemption> {
    if schedule(req, nodes, strategy, None).node.is_some() {
        return None;
    }
    let fits = |n: &Node, gone: &[&Running]| filter(req, &without(n, gone)).is_empty();
    let mut best: Option<Preemption> = None;
    for n in nodes {
        if !filter(req, n).iter().all(|r| matches!(r, Refusal::NoRoom { .. })) {
            continue;
        }
        let mut may: Vec<&Running> = running.get(&n.name).map(|v| v.iter().filter(|r| r.yields_to(req)).collect()).unwrap_or_default();
        may.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then(b.memory_mib.cmp(&a.memory_mib))
                .then(b.vcpus.total_cmp(&a.vcpus))
                .then_with(|| a.run.cmp(&b.run))
        });
        let mut gone: Vec<&Running> = vec![];
        for r in may {
            if fits(n, &gone) {
                break;
            }
            gone.push(r);
        }
        if gone.is_empty() || !fits(n, &gone) {
            continue;
        }
        // Put back any it fits without, highest priority first: fitting only gets harder as fewer
        // are stopped, so each one left is needed.
        for i in (0..gone.len()).rev() {
            let mut fewer = gone.clone();
            fewer.remove(i);
            if fits(n, &fewer) {
                gone = fewer;
            }
        }
        let mut victims: Vec<String> = gone.iter().map(|r| r.run.clone()).collect();
        victims.sort();
        let p = Preemption { node: n.name.clone(), max_priority: gone.iter().map(|r| r.priority).max().unwrap_or(i32::MIN), victims };
        let key = |p: &Preemption| (p.max_priority, p.victims.len(), p.node.clone());
        if best.as_ref().is_none_or(|b| key(&p) < key(b)) {
            best = Some(p);
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(name: &str, vcpus: f32, used: f32, mem: u64, used_mem: u64) -> Node {
        Node { name: name.into(), vcpus, used_vcpus: used, memory_mib: mem, used_memory_mib: used_mem, ..Node::default() }
    }

    fn req(vcpus: f32, mib: u64) -> Request {
        Request { vcpus, memory_mib: mib, ..Request::default() }
    }

    #[test]
    fn bin_pack_takes_the_fullest_node_that_fits_and_spread_the_emptiest() {
        let nodes = vec![node("a", 4.0, 0.0, 8192, 0), node("b", 4.0, 2.0, 8192, 6144), node("c", 4.0, 3.5, 8192, 7168)];
        let d = schedule(&req(1.0, 1024), &nodes, Strategy::BinPack, None);
        assert_eq!(d.node.as_deref(), Some("b"), "c has no vCPU left: {d:?}");
        assert_eq!(d.ranked, vec!["b", "a"]);
        assert_eq!(d.refused, vec![("c".into(), vec![Refusal::NoRoom { free_vcpus: 0.5, free_mib: 1024 }])]);
        assert_eq!(schedule(&req(1.0, 1024), &nodes, Strategy::Spread, None).node.as_deref(), Some("a"));
        assert_eq!(d.why_not(), "c (0.5 vCPU, 1024 MiB free)");
    }

    #[test]
    fn where_it_ran_before_only_breaks_ties() {
        let twins = vec![node("a", 2.0, 0.0, 4096, 0), node("b", 2.0, 0.0, 4096, 0)];
        assert_eq!(schedule(&req(1.0, 512), &twins, Strategy::BinPack, None).node.as_deref(), Some("a"), "the name");
        assert_eq!(schedule(&req(1.0, 512), &twins, Strategy::BinPack, Some("b")).node.as_deref(), Some("b"));
        let uneven = vec![node("a", 2.0, 0.0, 4096, 2048), node("b", 2.0, 0.0, 4096, 0)];
        assert_eq!(schedule(&req(1.0, 512), &uneven, Strategy::BinPack, Some("b")).node.as_deref(), Some("a"));
    }

    #[test]
    fn admission_full_labels_taints_and_ca_filter() {
        let mut n = node("n", 8.0, 0.0, 16384, 0);
        n.room_mib = Some(512);
        assert_eq!(filter(&req(1.0, 1024), &n), vec![Refusal::NoRoom { free_vcpus: 8.0, free_mib: 512 }], "its admission's room");
        n.room_mib = None;
        n.full = true;
        assert_eq!(filter(&req(1.0, 1024), &n), vec![Refusal::Full]);
        n.full = false;

        let mut r = req(1.0, 1024);
        r.node_selector.insert("gpu".into(), "a100".into());
        assert_eq!(filter(&r, &n), vec![Refusal::Label { key: "gpu".into(), want: "a100".into(), has: None }]);
        n.labels.insert("gpu".into(), "t4".into());
        assert_eq!(filter(&r, &n), vec![Refusal::Label { key: "gpu".into(), want: "a100".into(), has: Some("t4".into()) }]);
        n.labels.insert("gpu".into(), "a100".into());
        assert!(filter(&r, &n).is_empty());

        n.taints.push(Taint::parse("dedicated=ci").unwrap());
        assert_eq!(filter(&r, &n), vec![Refusal::Taint(Taint::parse("dedicated=ci").unwrap())]);
        r.tolerations.push(Taint::parse("dedicated").unwrap());
        assert!(filter(&r, &n).is_empty(), "a bare toleration takes any value");

        n.ca = Coverage::Widens(vec!["api.example.com".into()]);
        assert!(filter(&r, &n).is_empty(), "a CA it may widen is no reason");
        n.ca = Coverage::Refuses(vec!["api.example.com".into()]);
        assert_eq!(filter(&r, &n), vec![Refusal::Ca(vec!["api.example.com".into()])]);
        n.full = true;
        assert_eq!(filter(&r, &n).len(), 2, "every reason, not the first");
    }

    /// xorshift64*: reproducible from its seed, so a failure names one.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn random_node(rng: &mut Rng, i: usize) -> Node {
        let vcpus = (1 + rng.below(16)) as f32;
        let memory_mib = 1024 * (1 + rng.below(32));
        let mut n = Node {
            name: format!("n{}", rng.below(8 * (i as u64 + 1))),
            vcpus,
            used_vcpus: (rng.below(vcpus as u64 * 2 + 1) as f32) / 2.0,
            memory_mib,
            used_memory_mib: rng.below(memory_mib + 1),
            room_mib: (rng.below(2) == 0).then(|| rng.below(memory_mib + 1)),
            full: rng.below(10) == 0,
            ..Node::default()
        };
        if rng.below(3) == 0 {
            n.labels.insert("pool".into(), ["a", "b"][rng.below(2) as usize].into());
        }
        if rng.below(4) == 0 {
            n.taints.push(Taint { key: "dedicated".into(), value: Some(["ci", "gpu"][rng.below(2) as usize].into()) });
        }
        n.ca = match rng.below(6) {
            0 => Coverage::Refuses(vec!["x.example".into()]),
            1 => Coverage::Widens(vec!["x.example".into()]),
            _ => Coverage::Covers,
        };
        for (i, name) in ["npm-cache", "oci-mirror"].into_iter().enumerate() {
            if rng.below(2) == 0 {
                n.services.insert(name.into());
            }
            if rng.below(3) == 0 {
                n.volumes.insert(format!("v{i}"));
            }
            if rng.below(3) == 0 {
                n.zones.insert(format!("z{i}"));
            }
            if rng.below(4) == 0 {
                n.principals.insert(format!("spiffe://w.test/t/t0/z/z{i}/a/a{i}"));
            }
        }
        n
    }

    fn random_affinity(rng: &mut Rng, r: &mut Request) {
        for _ in 0..rng.below(3) {
            let mut a = Affinity { required: rng.below(3) == 0, ..Affinity::default() };
            if rng.below(2) == 0 {
                a.service = Some(["npm-cache", "oci-mirror"][rng.below(2) as usize].into());
            } else {
                a.volume = Some(format!("v{}", rng.below(2)));
            }
            r.affinity.push(a);
        }
        for _ in 0..rng.below(3) {
            let mut a = AntiAffinity { required: rng.below(3) == 0, ..AntiAffinity::default() };
            let i = rng.below(2);
            if rng.below(2) == 0 {
                a.zone = Some(format!("z{i}"));
            } else {
                a.principal = Some(format!("spiffe://w.test/t/t0/z/z{i}/a/a{i}"));
            }
            r.anti_affinity.push(a);
        }
    }

    fn random_request(rng: &mut Rng) -> Request {
        let mut r = Request { vcpus: (rng.below(8) as f32) / 2.0, memory_mib: 256 * rng.below(33), ..Request::default() };
        if rng.below(3) == 0 {
            r.node_selector.insert("pool".into(), ["a", "b"][rng.below(2) as usize].into());
        }
        if rng.below(3) == 0 {
            r.tolerations.push(Taint { key: "dedicated".into(), value: (rng.below(2) == 0).then(|| "ci".into()) });
        }
        if rng.below(2) == 0 {
            random_affinity(rng, &mut r);
        }
        r.priority = rng.below(5) as i32 - 2;
        r
    }

    /// For many random nodes and requests: the node chosen always has the room asked for, and every
    /// constraint holds; a node is refused exactly when a constraint fails; the decision doesn't
    /// depend on the order the nodes were listed in; and bin-pack's choice leaves no feasible node
    /// with less memory left.
    #[test]
    fn properties_over_random_clusters() {
        for seed in 1..=3000u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let count = rng.below(9) as usize;
            let mut nodes: Vec<Node> = (0..count).map(|i| random_node(&mut rng, i)).collect();
            // Names are unique, as enrolled nodes' are.
            nodes.sort_by(|a, b| a.name.cmp(&b.name));
            nodes.dedup_by(|a, b| a.name == b.name);
            let r = random_request(&mut rng);
            let last = (rng.below(2) == 0).then(|| format!("n{}", rng.below(8)));
            for strategy in [Strategy::BinPack, Strategy::Spread] {
                let d = schedule(&r, &nodes, strategy, last.as_deref());
                assert_eq!(d.ranked.len() + d.refused.len(), nodes.len(), "seed {seed}: every node is ranked or refused");
                assert_eq!(d.node, d.ranked.first().cloned(), "seed {seed}");
                for name in &d.ranked {
                    let n = nodes.iter().find(|n| &n.name == name).unwrap();
                    let (cpu, mem) = n.free();
                    assert!(!n.full && cpu + 1e-3 >= r.vcpus && mem >= r.memory_mib as i64, "seed {seed}: never over a node's room");
                    assert!(r.node_selector.iter().all(|(k, v)| n.labels.get(k) == Some(v)), "seed {seed}: labels");
                    assert!(n.taints.iter().all(|t| r.tolerations.iter().any(|x| x.tolerates(t))), "seed {seed}: taints");
                    assert!(!matches!(n.ca, Coverage::Refuses(_)), "seed {seed}: CA");
                    for a in r.affinity.iter().filter(|a| a.required) {
                        assert!(n.has(&a.near().unwrap()), "seed {seed}: required affinity");
                    }
                    for a in r.anti_affinity.iter().filter(|a| a.required) {
                        assert!(!n.runs(&a.away().unwrap()), "seed {seed}: required anti-affinity");
                    }
                }
                // The preferences met never rise down the ranking.
                let met: Vec<usize> =
                    d.ranked.iter().map(|name| r.preferences_met(nodes.iter().find(|n| &n.name == name).unwrap())).collect();
                assert!(met.windows(2).all(|w| w[0] >= w[1]), "seed {seed}: most preferences met first: {met:?}");
                for (name, why) in &d.refused {
                    let n = nodes.iter().find(|n| &n.name == name).unwrap();
                    assert_eq!(why, &filter(&r, n), "seed {seed}");
                    assert!(!why.is_empty());
                }
                let mut shuffled = nodes.clone();
                for i in (1..shuffled.len()).rev() {
                    shuffled.swap(i, rng.below(i as u64 + 1) as usize);
                }
                assert_eq!(schedule(&r, &shuffled, strategy, last.as_deref()), d, "seed {seed}: deterministic, whatever the order");
                if let (Strategy::BinPack, Some(chosen)) = (strategy, &d.node) {
                    let node = |name: &String| nodes.iter().find(|n| &n.name == name).unwrap();
                    let left = |name: &String| node(name).free().1;
                    let met = r.preferences_met(node(chosen));
                    assert!(
                        d.ranked.iter().filter(|o| r.preferences_met(node(o)) == met).all(|o| left(o) >= left(chosen)),
                        "seed {seed}: bin-pack takes the least room left, among the nodes meeting as many preferences"
                    );
                }
            }
        }
    }

    /// #682 re-review: a box whose record needs a node protocol (a zone that decodes a slash, 19)
    /// isn't placed on a node below it, or on one whose protocol isn't known yet.
    #[test]
    fn a_box_needing_a_protocol_skips_older_and_unknown_nodes() {
        let req = Request { vcpus: 1.0, memory_mib: 512, min_protocol: 19, ..Default::default() };
        let mut old = node("old", 4.0, 0.0, 4096, 0);
        old.protocol = Some(18);
        let unknown = node("unknown", 4.0, 0.0, 4096, 0);
        let mut new = node("new", 2.0, 0.0, 2048, 0);
        new.protocol = Some(19);
        let d = schedule(&req, &[old.clone(), unknown.clone(), new.clone()], Strategy::default(), None);
        assert_eq!(d.node.as_deref(), Some("new"), "{d:?}");
        assert_eq!(
            d.why_not(),
            "old (talks protocol 18, and the box's zone needs 19), unknown (its protocol isn't known yet, and the box's zone needs 19)"
        );
        let plain = Request { min_protocol: 0, ..req };
        assert!(filter(&plain, &old).is_empty() && filter(&plain, &unknown).is_empty(), "a plain box goes anywhere");
    }

    #[test]
    fn affinity_requires_or_prefers_and_anti_affinity_keeps_away() {
        let mut cached = node("cached", 4.0, 3.0, 8192, 0);
        cached.services.insert("npm-cache".into());
        let mut busy = node("busy", 4.0, 0.0, 8192, 0);
        busy.zones.insert("research".into());
        busy.principals.insert("spiffe://w.test/t/t0/z/research/a/r".into());
        let plain = node("plain", 4.0, 0.0, 8192, 4096);
        let nodes = vec![busy.clone(), cached.clone(), plain.clone()];

        // Preferred: the node with the service first, though bin-pack alone would take another.
        let mut r = req(0.5, 512);
        assert_eq!(schedule(&r, &nodes, Strategy::BinPack, None).node.as_deref(), Some("plain"), "bin-pack alone");
        r.affinity.push(Affinity { service: Some("npm-cache".into()), ..Affinity::default() });
        let d = schedule(&r, &nodes, Strategy::BinPack, None);
        assert_eq!(d.ranked, vec!["cached", "plain", "busy"], "the service's node, then bin-packed");
        // Required: the others are out, saying why.
        r.affinity[0].required = true;
        let d = schedule(&r, &nodes, Strategy::BinPack, None);
        assert_eq!(d.ranked, vec!["cached"]);
        assert_eq!(
            d.why_not(),
            "busy (no service npm-cache here, which the box requires), plain (no service npm-cache here, which the box requires)"
        );
        // A volume.
        let mut v = req(0.5, 512);
        v.affinity.push(Affinity { volume: Some("data".into()), required: true, ..Affinity::default() });
        assert!(schedule(&v, &nodes, Strategy::BinPack, None).node.is_none());
        let mut holder = plain.clone();
        holder.volumes.insert("data".into());
        assert_eq!(schedule(&v, &[busy.clone(), holder], Strategy::BinPack, None).node.as_deref(), Some("plain"));

        // Anti-affinity: preferred moves it off, required keeps it off.
        let mut a = req(0.5, 512);
        a.anti_affinity.push(AntiAffinity { zone: Some("research".into()), ..AntiAffinity::default() });
        let solo = vec![busy.clone(), node("free", 4.0, 0.0, 8192, 0)];
        assert_eq!(schedule(&req(0.5, 512), &solo, Strategy::Spread, Some("busy")).node.as_deref(), Some("busy"), "a tie, to where it ran");
        assert_eq!(schedule(&a, &solo, Strategy::Spread, Some("busy")).node.as_deref(), Some("free"));
        a.anti_affinity[0] =
            AntiAffinity { principal: Some("spiffe://w.test/t/t0/z/research/a/r".into()), required: true, ..AntiAffinity::default() };
        let d = schedule(&a, &[busy], Strategy::BinPack, None);
        assert_eq!(d.node, None);
        assert_eq!(d.refused[0].1, vec![Refusal::Away(Away::Principal("spiffe://w.test/t/t0/z/research/a/r".into()))]);
    }

    fn w(run: &str, tenant: &str, priority: i32, at_ms: i64) -> Waiter {
        Waiter { run: run.into(), tenant: tenant.into(), priority, at_ms }
    }

    #[test]
    fn priority_orders_a_tenants_own_runs_and_tenants_keep_their_places() {
        let order = |q: &[Waiter]| queue_order(q).into_iter().map(|w| w.run.as_str()).collect::<Vec<_>>().join(" ");
        // One tenant: by priority, FIFO within one.
        let one = vec![w("a", "t0", 0, 10), w("b", "t0", 5, 30), w("c", "t0", 0, 5), w("d", "t0", 5, 20), w("e", "t0", -1, 1)];
        assert_eq!(order(&one), "d b c a e");
        // t1 took places at 2 and 40. Marking its late run 1000 puts it in t1's first place, and
        // moves nothing of t0's: t0's runs fill t0's places (1, 5, 10, 20, 30) as before.
        let mut two = one.clone();
        two.push(w("x", "t1", 0, 2));
        two.push(w("y", "t1", 1000, 40));
        assert_eq!(order(&two), "d y b c a e x");
        let ahead_of = |me: &Waiter| ahead(me, &two).into_iter().map(|w| w.run.as_str()).collect::<Vec<_>>();
        assert_eq!(
            ahead_of(&w("new", "t1", 1000, 99)),
            ["d", "y", "b", "c", "a", "e"],
            "at 1000, still behind every place taken before it"
        );
        assert!(ahead_of(&w("new", "t0", 1000, 99)).is_empty(), "first of t0's own");
        assert_eq!(ahead_of(&two[0]), ["d", "y", "b", "c"], "a is t0's fourth run: its place is 20");
    }

    /// For many random queues over a few tenants: the order is a permutation and doesn't depend on
    /// the order listed; within a tenant a higher priority goes first, and FIFO within one; each
    /// tenant's runs hold exactly the places in line it took; with no priorities it is plain first
    /// come, first served; and a tenant changing its own runs' priorities moves no other tenant's
    /// run. `ahead` is exactly the runs before `me` in that order.
    #[test]
    fn queue_properties() {
        for seed in 1..=2000u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let q: Vec<Waiter> = (0..rng.below(12))
                .map(|i| w(&format!("r{i}"), ["t0", "t1", "t2"][rng.below(3) as usize], rng.below(4) as i32 - 1, rng.below(6) as i64))
                .collect();
            let order: Vec<&Waiter> = queue_order(&q);
            assert_eq!(order.len(), q.len(), "seed {seed}");
            let mut shuffled = q.clone();
            for i in (1..shuffled.len()).rev() {
                shuffled.swap(i, rng.below(i as u64 + 1) as usize);
            }
            let names = |o: Vec<&Waiter>| o.into_iter().map(|w| w.run.clone()).collect::<Vec<_>>();
            assert_eq!(names(queue_order(&shuffled)), names(order.clone()), "seed {seed}: whatever the order listed");
            for (i, a) in order.iter().enumerate() {
                for b in &order[i + 1..] {
                    if a.tenant == b.tenant {
                        assert!(
                            a.priority > b.priority || (a.priority == b.priority && a.at_ms <= b.at_ms),
                            "seed {seed}: within a tenant, by priority then FIFO"
                        );
                    }
                }
            }
            let flat: Vec<Waiter> = q.iter().map(|x| Waiter { priority: 0, ..x.clone() }).collect();
            let fifo = queue_order(&flat);
            assert!(fifo.windows(2).all(|p| p[0].at_ms <= p[1].at_ms), "seed {seed}: no priorities, first come, first served");
            // Each tenant holds exactly the places in line it took: priorities change which of its
            // runs is where, never which places are its.
            let tenants = |o: &[&Waiter]| o.iter().map(|w| w.tenant.clone()).collect::<Vec<_>>();
            assert_eq!(tenants(&order), tenants(&fifo), "seed {seed}: the places are the tenants' own");
            // t0 re-ranks its own runs: every other tenant's run stays where it was.
            let mut bumped = q.clone();
            for x in bumped.iter_mut().filter(|x| x.tenant == "t0") {
                x.priority = rng.below(2001) as i32 - 1000;
            }
            let before = names(order.clone());
            let after = names(queue_order(&bumped));
            for (i, r) in before.iter().enumerate() {
                if q.iter().any(|x| &x.run == r && x.tenant != "t0") {
                    assert_eq!(&after[i], r, "seed {seed}: t0's priorities moved {r}");
                }
            }
            for me in &q {
                let want: Vec<String> = before.iter().take_while(|r| *r != &me.run).cloned().collect();
                assert_eq!(names(ahead(me, &q)), want, "seed {seed}");
            }
        }
    }

    fn running(run: &str, vcpus: f32, memory_mib: u64, priority: i32, preemptible: bool) -> Running {
        Running { run: run.into(), vcpus, memory_mib, priority, preemptible }
    }

    #[test]
    fn preemption_stops_only_preemptible_boxes_of_lower_priority_and_as_few_as_it_can() {
        // n1 is full of: a preemptible batch box (priority 0), a protected one (priority 0), and a
        // preemptible one of priority 10.
        let nodes = vec![node("n1", 4.0, 4.0, 8192, 8192), node("n2", 2.0, 2.0, 4096, 4096)];
        let mut on = BTreeMap::new();
        on.insert(
            "n1".to_string(),
            vec![running("batch", 1.0, 2048, 0, true), running("kept", 1.0, 2048, 0, false), running("high", 2.0, 4096, 10, true)],
        );
        on.insert("n2".to_string(), vec![running("small-a", 1.0, 1024, -1, true), running("small-b", 1.0, 1024, -1, true)]);

        let mut r = req(1.0, 2048);
        r.priority = 5;
        let p = preempt(&r, &nodes, &on, Strategy::BinPack).unwrap();
        // n2 needs two victims of priority -1; n1 one of priority 0. The lowest highest-priority
        // victim wins: n2's.
        assert_eq!(p, Preemption { node: "n2".into(), victims: vec!["small-a".into(), "small-b".into()], max_priority: -1 });

        on.remove("n2");
        let p = preempt(&r, &nodes, &on, Strategy::BinPack).unwrap();
        assert_eq!(p.victims, ["batch"], "never kept (not preemptible) nor high (not lower)");

        r.priority = 0;
        assert!(preempt(&r, &nodes, &on, Strategy::BinPack).is_none(), "an equal priority stops nothing");
        r.priority = 20;
        r.vcpus = 4.0;
        r.memory_mib = 8192;
        assert!(preempt(&r, &nodes, &on, Strategy::BinPack).is_none(), "stopping all it may still leaves no room: kept stays");

        // Room is all it makes: a node out for a label stays out.
        let mut r = req(1.0, 2048);
        r.priority = 5;
        r.node_selector.insert("gpu".into(), "a100".into());
        assert!(preempt(&r, &nodes, &on, Strategy::BinPack).is_none());
        // And nothing is stopped when a node may take it already.
        let roomy = vec![nodes[0].clone(), node("n3", 4.0, 0.0, 8192, 0)];
        assert!(preempt(&req(1.0, 2048), &roomy, &on, Strategy::BinPack).is_none());
    }

    /// For many random clusters and the boxes on them: preemption is chosen only when no node may
    /// take the box; every victim is preemptible, of lower priority, and on the node chosen; with
    /// them stopped the box fits there, and with any one of them kept it doesn't; when none is
    /// chosen, no node can be made to fit by stopping every box it may stop there; and of the nodes
    /// that can, none has a lower highest-priority victim.
    #[test]
    fn preemption_properties() {
        let mut chosen = 0;
        for seed in 1..=3000u64 {
            let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            let count = 1 + rng.below(5) as usize;
            let mut nodes: Vec<Node> = (0..count)
                .map(|i| {
                    let mut n = random_node(&mut rng, i);
                    n.name = format!("n{i}");
                    n.full = rng.below(20) == 0;
                    n
                })
                .collect();
            let mut on: BTreeMap<String, Vec<Running>> = BTreeMap::new();
            for n in nodes.iter_mut() {
                let boxes: Vec<Running> = (0..rng.below(5))
                    .map(|j| {
                        running(
                            &format!("{}-r{j}", n.name),
                            (1 + rng.below(4)) as f32 / 2.0,
                            256 * (1 + rng.below(16)),
                            rng.below(5) as i32 - 2,
                            rng.below(3) != 0,
                        )
                    })
                    .collect();
                // What its boxes hold is what it uses (at most).
                n.used_vcpus = boxes.iter().map(|b| b.vcpus).sum::<f32>().min(n.vcpus);
                n.used_memory_mib = boxes.iter().map(|b| b.memory_mib).sum::<u64>().min(n.memory_mib);
                on.insert(n.name.clone(), boxes);
            }
            let mut r = random_request(&mut rng);
            r.vcpus = (1 + rng.below(8)) as f32 / 2.0;
            r.memory_mib = 512 * (1 + rng.below(16));
            let p = preempt(&r, &nodes, &on, Strategy::BinPack);
            let placeable = schedule(&r, &nodes, Strategy::BinPack, None).node.is_some();
            let by_name = |name: &str| nodes.iter().find(|n| n.name == name).unwrap();
            // What stopping every box it may stop on each node gives.
            let all_gone = |n: &Node| -> bool {
                let may: Vec<&Running> = on[&n.name].iter().filter(|b| b.yields_to(&r)).collect();
                !may.is_empty()
                    && filter(&r, n).iter().all(|x| matches!(x, Refusal::NoRoom { .. }))
                    && filter(&r, &without(n, &may)).is_empty()
            };
            match &p {
                None => assert!(placeable || nodes.iter().all(|n| !all_gone(n)), "seed {seed}: no preemption that would work is missed"),
                Some(p) => {
                    chosen += 1;
                    assert!(!placeable, "seed {seed}: never when a node may take it");
                    let n = by_name(&p.node);
                    let boxes = &on[&p.node];
                    let gone: Vec<&Running> = p.victims.iter().map(|v| boxes.iter().find(|b| &b.run == v).expect("on its node")).collect();
                    assert!(!gone.is_empty());
                    assert!(gone.iter().all(|b| b.preemptible && b.priority < r.priority), "seed {seed}: only those that yield");
                    assert_eq!(p.max_priority, gone.iter().map(|b| b.priority).max().unwrap());
                    assert!(filter(&r, &without(n, &gone)).is_empty(), "seed {seed}: it fits with them stopped");
                    for i in 0..gone.len() {
                        let mut kept = gone.clone();
                        kept.remove(i);
                        assert!(!filter(&r, &without(n, &kept)).is_empty(), "seed {seed}: each victim is needed");
                    }
                    // On each node, the lowest k such that stopping every box it may stop of
                    // priority k or less makes room: no node does with less than the choice's.
                    for other in nodes.iter().filter(|o| all_gone(o)) {
                        let least = (-2..=2)
                            .find(|k| {
                                let upto: Vec<&Running> = on[&other.name].iter().filter(|b| b.yields_to(&r) && b.priority <= *k).collect();
                                filter(&r, &without(other, &upto)).is_empty()
                            })
                            .unwrap();
                        assert!(p.max_priority <= least, "seed {seed}: never a needlessly high victim ({} on {})", least, other.name);
                    }
                }
            }
        }
        assert!(chosen > 100, "the generator makes preemption happen ({chosen})");
    }
}
