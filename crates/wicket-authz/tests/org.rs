//! The org layer (#51): the installation's org policy, compiled into block 0, over every zone.
//! - its forbids beat every grant and every zone;
//! - its ceiling is hard: a request a zone allows but the org doesn't is Forbidden, and no grant
//!   lifts it (only the zone layer is escalatable);
//! - a child box can't shed it (block 0's checks carry into every spawn link);
//! - no org policy: block 0 is what it was.

mod common;
use common::*;
use wicket_authz::*;
use wicket_core::RiskClass;

fn org(http: Option<Vec<HttpMatch>>, forbid: Vec<HttpMatch>) -> OrgLayer {
    OrgLayer { version: "v1".into(), http, forbid, spawn: None, msg_from: None, inject: None }
}

fn host(h: &str) -> HttpMatch {
    HttpMatch { hosts: vec![HostPat::Exact(h.into())], ..Default::default() }
}

/// The depth-5 chain of `common`, with `org` in block 0, with and without the leaf's grant.
fn chain(org: Option<OrgLayer>) -> (Keys, Token, Token) {
    let keys = Keys::new(5);
    let mut cs = ceilings(5, &keys);
    cs[0].org = org;
    let t = mint_chain(&cs, &keys);
    let g = grant(&t, &keys.approver, &leaf_grant(5)).unwrap();
    (keys, t, g)
}

fn at_leaf(action: Action) -> Request {
    Request { action, ..base_request(5) }
}

fn kind(d: &Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::NeedsGrant(_) => "needs-grant",
        Decision::Forbidden(_) => "forbidden",
    }
}

#[test]
fn an_org_forbid_beats_the_zone_and_a_grant() {
    let merge = at_leaf(http("PUT", "api.github.com", "/repos/acme/api/pulls/7/merge", RiskClass::R4ExecOrPrivilege));
    let read = at_leaf(http("GET", "api.github.com", "/repos/acme/api/pulls/7", RiskClass::R1ReadScoped));
    // Without the org forbid: the grant allows the merge.
    let (k, _, g) = chain(None);
    assert_eq!(kind(&load_ok(&g, &k).decide(&merge)), "allow");
    // Forbid PUT on api.github.com: the grant no longer helps, and GETs are untouched.
    let f = HttpMatch { methods: Some(vec!["PUT".into()]), ..host("api.github.com") };
    let (k, _, g) = chain(Some(org(None, vec![f])));
    let l = load_ok(&g, &k);
    assert_eq!(kind(&l.decide(&merge)), "forbidden");
    assert_eq!(kind(&l.decide(&read)), "allow");
    // A risk forbid: R4 and above, anywhere.
    let f = HttpMatch { min_risk: Some(risk_level(RiskClass::R4ExecOrPrivilege)), ..Default::default() };
    let (k, _, g) = chain(Some(org(None, vec![f])));
    assert_eq!(kind(&load_ok(&g, &k).decide(&merge)), "forbidden");
}

#[test]
fn the_org_ceiling_is_hard_and_no_grant_lifts_it() {
    // The org allows only GETs, anywhere under /repos/acme/api.
    let ceiling = HttpMatch {
        methods: Some(vec!["GET".into(), "HEAD".into()]),
        paths: vec![PathPat::Glob("/repos/acme/api/**".into())],
        ..Default::default()
    };
    let (k, t, g) = chain(Some(org(Some(vec![ceiling]), vec![])));
    let merge = at_leaf(http("PUT", "api.github.com", "/repos/acme/api/pulls/7/merge", RiskClass::R4ExecOrPrivilege));
    // The zone would need a grant for it; the org doesn't allow it at all: Forbidden, not NeedsGrant.
    assert_eq!(kind(&load_ok(&t, &k).decide(&merge)), "forbidden");
    // And the grant the zone would take doesn't lift the org ceiling.
    assert_eq!(kind(&load_ok(&g, &k).decide(&merge)), "forbidden");
    // Within both: allowed.
    let read = at_leaf(http("GET", "api.github.com", "/repos/acme/api/pulls/7", RiskClass::R1ReadScoped));
    assert_eq!(kind(&load_ok(&t, &k).decide(&read)), "allow");
    // Outside the zone, within the org: still escalatable (the zone layer is).
    let outside_zone = at_leaf(http("GET", "docs.rs", "/repos/acme/api/x", RiskClass::R1ReadScoped));
    assert_eq!(kind(&load_ok(&t, &k).decide(&outside_zone)), "needs-grant");
}

#[test]
fn a_child_cant_shed_the_org_layer() {
    // Block 0 forbids spawning anything but img:agent; every link below allows img:rust.
    let o =
        OrgLayer { spawn: Some(vec![SpawnMatch { images: Some(vec!["img:agent".into()]), ..Default::default() }]), ..org(None, vec![]) };
    let (k, t, _) = chain(Some(o));
    let spawn = |img: &str| {
        at_leaf(Action::Spawn { image: img.into(), isolation: 2, mem_bytes: 256 << 20, cpus_milli: 250, pids: 64, timeout_s: 900 })
    };
    let l = load_ok(&t, &k);
    assert_eq!(kind(&l.decide(&spawn("img:rust"))), "forbidden");
    assert_eq!(kind(&l.decide(&spawn("img:agent"))), "allow");
}

#[test]
fn messages_and_injections_under_the_org_layer() {
    // Block 0 alone (the depth-5 leaf accepts no messages of its own).
    let keys = Keys::new(0);
    let c = ceilings(0, &keys).remove(0);
    let read = Request { action: http("GET", "api.github.com", "/repos/acme/api/pulls/7", RiskClass::R1ReadScoped), ..base_request(0) };
    let msg = base_request(0);
    let decide = |o: Option<OrgLayer>, r: &Request| {
        let mut c = c.clone();
        c.org = o;
        kind(&load_ok(&mint(&keys.root, TENANT, "t", &c).unwrap(), &keys).decide(r))
    };
    // The zone accepts messages from ops, and allows its injection.
    assert_eq!((decide(None, &msg), decide(None, &read)), ("allow", "allow"));
    // The org accepts messages from nobody, and allows no injection.
    let o = OrgLayer { msg_from: Some(vec![]), inject: Some(vec![]), ..org(None, vec![]) };
    assert_eq!((decide(Some(o.clone()), &msg), decide(Some(o), &read)), ("forbidden", "forbidden"));
    let o = OrgLayer { msg_from: Some(vec!["ops".into()]), inject: Some(vec![GH_INJECT.into()]), ..org(None, vec![]) };
    assert_eq!((decide(Some(o.clone()), &msg), decide(Some(o), &read)), ("allow", "allow"));
}

#[test]
fn like_patterns_match_as_cedar_does() {
    let re = |p: &str| regex::Regex::new(&wicket_authz::generator::like_regex(p)).unwrap();
    assert!(re("/admin/*").is_match("/admin/a/b"), "Cedar's * crosses /");
    assert!(!re("/admin/*").is_match("/admins"));
    assert!(re(r"/a\*b").is_match("/a*b") && !re(r"/a\*b").is_match("/axb"));
    assert!(re("/a.b").is_match("/a.b") && !re("/a.b").is_match("/axb"), "regex metacharacters are literal");
}

#[test]
fn no_org_policy_leaves_block_zero_as_it_was() {
    let keys = Keys::new(0);
    let c = ceilings(0, &keys).remove(0);
    let printed = mint(&keys.root, TENANT, "t", &c).unwrap().print();
    assert!(!printed.contains("policy("), "{printed}");
    let mut with = c.clone();
    with.org = Some(org(None, vec![]));
    assert!(mint(&keys.root, TENANT, "t", &with).unwrap().print().contains("policy("));
}
