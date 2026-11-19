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
//! **Score:** of the nodes left, bin-pack (the default: the one left with the least memory, then the
//! fewest vCPUs, once the box is on it, so the fewest nodes are kept busy) or spread (the most).
//! Ties go to `last` (where the box ran before), then to the name, so the same inputs always give
//! the same node.

use std::collections::BTreeMap;
use std::fmt;
use wicket_core::placement::Taint;

/// What a box asks for: its limits, as requests, and its placement constraints.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Request {
    pub vcpus: f32,
    pub memory_mib: u64,
    pub node_selector: BTreeMap<String, String>,
    pub tolerations: Vec<Taint>,
}

impl Request {
    pub fn of(m: &wicket_core::Manifest) -> Request {
        Request {
            vcpus: m.zone.limits.cpus,
            memory_mib: m.zone.limits.memory_bytes().unwrap_or(0) >> 20,
            node_selector: m.placement.node_selector.clone(),
            tolerations: m.placement.tolerations(),
        }
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
}

impl Node {
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
    NoRoom { free_vcpus: f32, free_mib: i64 },
    Label { key: String, want: String, has: Option<String> },
    Taint(Taint),
    Ca(Vec<String>),
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
        by_room.then_with(|| (Some(a.name.as_str()) != last).cmp(&(Some(b.name.as_str()) != last))).then_with(|| a.name.cmp(&b.name))
    });
    refused.sort_by(|a, b| a.0.cmp(&b.0));
    let ranked: Vec<String> = ok.iter().map(|n| n.name.clone()).collect();
    Decision { node: ranked.first().cloned(), ranked, refused }
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
        n
    }

    fn random_request(rng: &mut Rng) -> Request {
        let mut r = Request { vcpus: (rng.below(8) as f32) / 2.0, memory_mib: 256 * rng.below(33), ..Request::default() };
        if rng.below(3) == 0 {
            r.node_selector.insert("pool".into(), ["a", "b"][rng.below(2) as usize].into());
        }
        if rng.below(3) == 0 {
            r.tolerations.push(Taint { key: "dedicated".into(), value: (rng.below(2) == 0).then(|| "ci".into()) });
        }
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
                }
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
                    let left = |name: &String| nodes.iter().find(|n| &n.name == name).unwrap().free().1;
                    assert!(d.ranked.iter().all(|o| left(o) >= left(chosen)), "seed {seed}: bin-pack takes the least room left");
                }
            }
        }
    }
}
