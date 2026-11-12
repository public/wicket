//! Links between boxes (design §4.3, §8.2; issue #6): who may connect to whose port, and the names
//! and addresses a link gets inside the connecting box. Pure: the ledger, the relay and the boxes
//! live elsewhere (wicket-proxy's `link` module).
//!
//! A link carries authority: whoever connects to a box can make it do whatever its zone allows. So
//! a link opens without a human only when
//! - the target is the connector's own child (connectable by default), or it exposed the port and
//!   its zone's `accept_from` lists the connector's zone; and
//! - the target's reach is within the connector's ([`subset::reach_within`]).
//!
//! Anything else needs a human's approval of exactly that link. A target that never exposed the port
//! (and isn't the connector's child) is refused outright: the target has to consent.

use crate::manifest::ZoneSpec;
use crate::subset;
use std::net::Ipv4Addr;

/// The in-box addresses links get: `198.18.1.1` onwards, one per linked name, inside the benchmarking
/// block wicket.internal (`198.18.0.1`) comes from. `wicket-entry` adds them to the box's loopback at
/// start (it can't later: it drops `NET_ADMIN`).
pub const POOL_START: Ipv4Addr = Ipv4Addr::new(198, 18, 1, 1);
pub const POOL_SIZE: u32 = 32;
/// Linked names live under wicket's own: `<name>.wicket.internal`.
pub const DOMAIN: &str = "wicket.internal";

/// One end of a link, as the ledger knows it.
#[derive(Clone, Copy, Debug)]
pub struct End<'a> {
    pub run: &'a str,
    pub parent_run: Option<&'a str>,
    pub zone_name: &'a str,
    pub accept_from: &'a [String],
    /// The end's zone, if wicket knows it (from the caller's own spawn record or from the end's
    /// `expose`). Unknown is treated as not contained.
    pub zone: Option<&'a ZoneSpec>,
}

/// Why a link may open without a human.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Basis {
    /// The target is the connector's own child.
    Child,
    /// The target exposed the port, and its zone accepts links from the connector's zone.
    Accepted,
    /// `link`: the caller controls both ends (itself or its own children).
    Controller,
}

impl Basis {
    pub fn as_str(self) -> &'static str {
        match self {
            Basis::Child => "child",
            Basis::Accepted => "accept_from",
            Basis::Controller => "both ends are the caller's",
        }
    }
}

/// The outcome of a policy check that didn't refuse: a basis, plus what a human must approve (empty:
/// nothing). A link with no basis always needs a human.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub basis: Option<Basis>,
    pub needs_human: Vec<String>,
}

impl Decision {
    pub fn allowed(&self) -> bool {
        self.needs_human.is_empty()
    }
}

/// The target's reach must be within the connector's.
fn containment(connector: &End<'_>, target: &End<'_>, v: &mut Vec<String>) {
    match (connector.zone, target.zone) {
        (Some(c), Some(t)) => {
            if let Err(e) = subset::reach_within(c, t) {
                v.extend(e.into_iter().map(|x| format!("zone {} reaches beyond zone {}: {x}", t.name, c.name)));
            }
        }
        _ => v.push(format!("wicket can't prove zone {}'s reach is within zone {}'s", target.zone_name, connector.zone_name)),
    }
}

/// `connect(target, port)` from `caller`. Err: refused (no human can approve it).
pub fn connect(caller: &End<'_>, target: &End<'_>, exposed: bool) -> Result<Decision, String> {
    if caller.run == target.run {
        return Err("a box can't link to itself: use localhost".into());
    }
    let mut needs = Vec::new();
    let basis = if target.parent_run == Some(caller.run) {
        Some(Basis::Child)
    } else if !exposed {
        return Err(format!("{} has not exposed that port (it must call expose first)", target.run));
    } else if target.accept_from.iter().any(|z| z == caller.zone_name) {
        Some(Basis::Accepted)
    } else {
        needs.push(format!(
            "zone {} does not accept links from zone {} (its accept_from does not list it)",
            target.zone_name, caller.zone_name
        ));
        None
    };
    containment(caller, target, &mut needs);
    Ok(Decision { basis, needs_human: needs })
}

/// `link(from, to, port)` by `caller`, which must control both ends: each is the caller or one of
/// its own children. The connector is `from`, so `to`'s reach must be within `from`'s.
pub fn link(caller: &str, from: &End<'_>, to: &End<'_>) -> Result<Decision, String> {
    if from.run == to.run {
        return Err("a box can't link to itself: use localhost".into());
    }
    for e in [from, to] {
        if e.run != caller && e.parent_run != Some(caller) {
            return Err(format!("{} is neither you nor one of your children: use connect, with its consent (expose)", e.run));
        }
    }
    let mut needs = Vec::new();
    containment(from, to, &mut needs);
    Ok(Decision { basis: Some(Basis::Controller), needs_human: needs })
}

/// A DNS label from a box's name: lowercase letters, digits and `-`, at most 40 characters, never
/// empty, never `wicket` (which would shadow nothing, but reads as wicket's own).
pub fn label(name: &str) -> String {
    let mut s: String = name
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(40)
        .collect();
    s = s.trim_end_matches('-').to_string();
    if s.is_empty() || s == "wicket" {
        s = format!("box-{s}").trim_end_matches('-').to_string();
    }
    s
}

/// A name a connecting box already uses: `name` (the DNS label) at `addr`, for the box `to_run`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Named {
    pub name: String,
    pub addr: Ipv4Addr,
    pub to_run: String,
}

/// The name and address a new link to `to_run` gets in a box that already has `used`. The same
/// target keeps its name and address (several ports share them); another target with the same
/// wanted name gets `-2`, `-3`, … Err when the box's address pool is used up.
pub fn allocate(used: &[Named], to_run: &str, wanted: &str) -> Result<(String, Ipv4Addr), String> {
    if let Some(n) = used.iter().find(|n| n.to_run == to_run) {
        return Ok((n.name.clone(), n.addr));
    }
    let base = label(wanted);
    let mut name = base.clone();
    let mut i = 2;
    while used.iter().any(|n| n.name == name) {
        name = format!("{base}-{i}");
        i += 1;
    }
    let start = u32::from(POOL_START);
    let addr = (start..start + POOL_SIZE)
        .map(Ipv4Addr::from)
        .find(|a| used.iter().all(|n| n.addr != *a))
        .ok_or_else(|| format!("this box already links to {POOL_SIZE} boxes, the most it can"))?;
    Ok((name, addr))
}

/// Whether `a` is one of the link pool's addresses.
pub fn in_pool(a: Ipv4Addr) -> bool {
    let (s, x) = (u32::from(POOL_START), u32::from(a));
    x >= s && x < s + POOL_SIZE
}

/// The box's hosts file: localhost, wicket's own name, and one line per open link name.
pub fn hosts_file(names: &[(String, Ipv4Addr)]) -> String {
    let mut s = String::from("127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n198.18.0.1\twicket.internal\n");
    let mut seen = std::collections::BTreeSet::new();
    for (name, addr) in names {
        if seen.insert(name.clone()) {
            s.push_str(&format!("{addr}\t{name}.{DOMAIN}\n"));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Manifest;

    fn zone(yaml: &str) -> ZoneSpec {
        Manifest::from_yaml(&format!("task: t\nprogram: {{ name: p, command: [x] }}\nzone: {yaml}\n")).unwrap().zone
    }

    fn end<'a>(run: &'a str, parent: Option<&'a str>, zone_name: &'a str, accept: &'a [String], z: Option<&'a ZoneSpec>) -> End<'a> {
        End { run, parent_run: parent, zone_name, accept_from: accept, zone: z }
    }

    #[test]
    fn children_are_connectable_by_default_others_need_consent_and_permission() {
        let wide = zone("{ name: lead, reach: [{ host: example.com, methods: [GET], paths: ['/**'] }] }");
        let narrow = zone("{ name: lead.svc, reach: [{ host: example.com, methods: [GET], paths: ['/docs/**'] }] }");
        let none: Vec<String> = vec![];
        let lead = end("run_lead", None, "lead", &none, Some(&wide));
        let child = end("run_svc", Some("run_lead"), "lead.svc", &none, Some(&narrow));

        // Own child, unexposed: allowed.
        let d = connect(&lead, &child, false).unwrap();
        assert_eq!(d.basis, Some(Basis::Child));
        assert!(d.allowed(), "{d:?}");

        // Someone else's box: must have exposed the port, or it's refused outright.
        let other = end("run_other", None, "other", &none, Some(&narrow));
        assert!(connect(&lead, &other, false).unwrap_err().contains("has not exposed"));
        // Exposed but its zone doesn't accept lead's: a human decides.
        let d = connect(&lead, &other, true).unwrap();
        assert_eq!(d.basis, None);
        assert!(d.needs_human[0].contains("does not accept links from zone lead"), "{d:?}");
        // Exposed and accepting: allowed.
        let acc = vec!["lead".to_string()];
        let accepting = end("run_other", None, "other", &acc, Some(&narrow));
        let d = connect(&lead, &accepting, true).unwrap();
        assert_eq!((d.basis, d.allowed()), (Some(Basis::Accepted), true));

        // A child connecting to its parent is not the parent's child: it needs the parent's consent.
        assert!(connect(&child, &lead, false).is_err());
        assert!(connect(&lead, &lead, false).unwrap_err().contains("itself"));
    }

    #[test]
    fn a_target_reaching_beyond_the_connector_needs_a_human() {
        let narrow = zone("{ name: n, reach: [{ host: example.com, methods: [GET], paths: ['/docs/**'] }] }");
        let wide = zone("{ name: w, reach: [{ host: example.com, methods: [GET, POST], paths: ['/**'] }] }");
        let creds = zone(
            "{ name: c, reach: [{ host: example.com, methods: [GET], paths: ['/docs/**'] }], inject: [{ host: example.com, header: authorization, format: 'Bearer {secret}', secret: s }] }",
        );
        let acc = vec!["n".to_string()];
        let none: Vec<String> = vec![];
        let conn = end("run_n", None, "n", &none, Some(&narrow));
        // A child whose zone a human approved beyond its parent's: connecting needs a human too.
        let d = connect(&conn, &end("run_w", Some("run_n"), "w", &none, Some(&wide)), false).unwrap();
        assert_eq!(d.basis, Some(Basis::Child));
        assert!(!d.allowed() && d.needs_human.iter().any(|x| x.contains("reaches beyond") && x.contains("POST")), "{d:?}");
        // A credential the connector doesn't hold is authority too.
        let d = connect(&conn, &end("run_c", None, "c", &acc, Some(&creds)), true).unwrap();
        assert!(!d.allowed() && d.needs_human.iter().any(|x| x.contains("inject")), "{d:?}");
        // An unknown zone is not contained.
        let d = connect(&conn, &end("run_u", Some("run_n"), "u", &none, None), false).unwrap();
        assert!(d.needs_human[0].contains("can't prove"), "{d:?}");
        // The reverse direction is fine: the wide box may connect to the narrow one.
        let wc = end("run_w", None, "w", &none, Some(&wide));
        assert!(connect(&wc, &end("run_n", Some("run_w"), "n", &none, Some(&narrow)), false).unwrap().allowed());
    }

    #[test]
    fn link_needs_both_ends_under_the_caller() {
        let z = zone("{ name: lead.a }");
        let w = zone("{ name: lead.b, reach: [{ host: example.com, methods: [GET], paths: ['/'] }] }");
        let none: Vec<String> = vec![];
        let a = end("run_a", Some("run_lead"), "lead.a", &none, Some(&z));
        let b = end("run_b", Some("run_lead"), "lead.b", &none, Some(&w));
        let stranger = end("run_x", Some("run_other"), "x", &none, Some(&z));
        // b reaches example.com, a doesn't: linking a → b would lend a that reach.
        let d = link("run_lead", &a, &b).unwrap();
        assert_eq!(d.basis, Some(Basis::Controller));
        assert!(!d.allowed());
        // b → a is contained.
        assert!(link("run_lead", &b, &a).unwrap().allowed());
        assert!(link("run_lead", &a, &stranger).unwrap_err().contains("neither you nor one of your children"));
        assert!(link("run_lead", &a, &a).is_err());
    }

    #[test]
    fn names_and_addresses_are_allocated_per_box() {
        let mut used = vec![];
        let (n, a) = allocate(&used, "run_1", "Chrome_Box").unwrap();
        assert_eq!((n.as_str(), a), ("chrome-box", POOL_START));
        used.push(Named { name: n, addr: a, to_run: "run_1".into() });
        // The same target keeps its name and address; another with the same name gets a suffix.
        assert_eq!(allocate(&used, "run_1", "other").unwrap(), ("chrome-box".to_string(), POOL_START));
        let (n2, a2) = allocate(&used, "run_2", "chrome-box").unwrap();
        assert_eq!((n2.as_str(), a2), ("chrome-box-2", Ipv4Addr::new(198, 18, 1, 2)));
        assert!(in_pool(a2) && !in_pool(Ipv4Addr::new(198, 18, 0, 1)));
        // The pool is finite.
        let full: Vec<Named> = (0..POOL_SIZE)
            .map(|i| Named { name: format!("n{i}"), addr: Ipv4Addr::from(u32::from(POOL_START) + i), to_run: format!("run_{i}") })
            .collect();
        assert!(allocate(&full, "run_new", "x").is_err());
        assert_eq!(label("--"), "box");
        assert_eq!(label("wicket"), "box-wicket");
        let h = hosts_file(&[("svc".into(), POOL_START)]);
        assert!(h.contains("198.18.0.1\twicket.internal\n") && h.contains("198.18.1.1\tsvc.wicket.internal\n"));
    }
}
