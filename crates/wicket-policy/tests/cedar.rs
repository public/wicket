//! #51: Cedar, compiled into tokens.
//! - every example and subset-test zone's Cedar compiles back to exactly the zone fields
//!   `Ceiling::from_zone` gives (so the token's zone layer is what it was, and CompiledZone's
//!   agreement with tokens carries over);
//! - what the compiler can't put at the edge is a compile error, construct by construct;
//! - conditions on the principal are decided at mint;
//! - **differentially**: Cedar's own `is_authorized` (org and zone as separate sets) against the
//!   compiled token's decision, over generated org policies and requests. Allow, NeedsGrant and
//!   Forbidden must agree; any disagreement fails.

#[path = "../../wicket-authz/tests/common/mod.rs"]
mod common;

use cedar_policy::{Authorizer, Context, Decision as CDecision, Entities, Entity, EntityUid, Request as CRequest, RestrictedExpression};
use common::{all_zones, Keys, Rng, T0, TENANT};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::str::FromStr;
use wicket_authz::*;
use wicket_core::{RiskClass, ZoneSpec};
use wicket_policy::{compile, MintCtx, OrgPolicy};

/// A ceiling's zone fields in a canonical form: one reach rule per (rule, path), rules with no method
/// or path dropped (they allow nothing), lists sorted.
fn canon(c: &Ceiling) -> Ceiling {
    let mut c = c.clone();
    let mut reach: Vec<Reach> = c
        .reach
        .iter()
        .filter(|r| r.methods.iter().any(|m| wicket_policy::schema::METHODS.contains(&m.to_ascii_uppercase().as_str())))
        .flat_map(|r| {
            r.paths.iter().map(move |p| Reach {
                host: r.host.clone(),
                methods: r
                    .methods
                    .iter()
                    .map(|m| m.to_ascii_uppercase())
                    .filter(|m| wicket_policy::schema::METHODS.contains(&m.as_str()))
                    .collect(),
                paths: vec![p.clone()],
                allow_dangerous: r.allow_dangerous,
            })
        })
        .collect();
    reach.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    c.reach = reach;
    let mut forbid: Vec<Forbid> =
        c.forbid.iter().flat_map(|f| f.paths.iter().map(move |p| Forbid { host: f.host.clone(), paths: vec![p.clone()] })).collect();
    forbid.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    c.forbid = forbid;
    c.accept_from.sort();
    c.accept_from.dedup();
    c.inject.sort();
    c.inject.dedup();
    c.spawn.images.sort();
    c.spawn.images.dedup();
    c
}

#[test]
fn every_zones_cedar_compiles_back_to_its_zone_fields() {
    let keys = Keys::new(0);
    let zones = all_zones();
    assert!(zones.len() > 40);
    for z in &zones {
        let base = Ceiling::from_zone(z, "b0", T0 + 3600, vec![keys.approver.public()]).unwrap();
        let c = wicket_policy::ceiling(z, "b0", T0 + 3600, vec![keys.approver.public()], &[], None)
            .unwrap_or_else(|e| panic!("zone {}: {e}\n{}", z.name, wicket_policy::zone::cedar(z, &base)));
        assert_eq!(canon(&c), canon(&base), "zone {}", z.name);
    }
}

fn mint() -> MintCtx {
    MintCtx { zone: "dev-api".into(), tenant: TENANT.into(), principal: "human:alex".into(), depth: 0, groups: ["dev".to_string()].into() }
}

fn org(text: &str) -> Result<OrgLayer, String> {
    let p = OrgPolicy::parse(text, "[]").map_err(|e| e.to_string())?;
    p.layer(&mint()).map_err(|e| e.to_string())
}

#[test]
fn what_cant_be_decided_at_the_edge_doesnt_compile() {
    let http = r#"action in [Action::"GET", Action::"PUT"]"#;
    for (why, policy) in [
        ("a negated path", format!(r#"permit(principal, {http}, resource) when {{ !resource.path_matches.contains("/a/**") }};"#)),
        ("a wildcard inside a host", format!(r#"permit(principal, {http}, resource) when {{ resource.host like "a*.example.com" }};"#)),
        ("has", format!(r#"permit(principal, {http}, resource) when {{ resource has host }};"#)),
        ("if", format!(r#"permit(principal, {http}, resource) when {{ if context.risk > 1 then true else false }};"#)),
        ("a forbid on spawn", r#"forbid(principal, action == Action::"spawn", resource) when { context.memory > 100 };"#.into()),
        ("an isolation ceiling", r#"permit(principal, action == Action::"spawn", resource) when { context.isolation <= 1 };"#.into()),
        (
            "a half-named injection",
            r#"permit(principal, action == Action::"inject", resource == Secret::"s") when { context.host == "h" };"#.into(),
        ),
        ("an unknown attribute", format!(r#"permit(principal, {http}, resource) when {{ resource.query == "x" }};"#)),
        ("a Box by name", format!(r#"permit(principal == Box::"b", {http}, resource);"#)),
        ("a template", format!(r#"permit(principal == ?principal, {http}, resource);"#)),
    ] {
        assert!(org(&policy).is_err(), "{why} compiled: {policy}");
    }
    // Strict validation: an attribute some of the scope's actions don't have.
    assert!(org(r#"permit(principal, action, resource) when { resource.host == "x" };"#).unwrap_err().contains("validate"));
}

#[test]
fn the_principal_is_decided_at_mint() {
    let p = r#"
        permit(principal, action, resource);
        forbid(principal in Group::"dev", action in [Action::"DELETE"], resource) when { resource.host == "prod.example.com" };
        forbid(principal, action in [Action::"PUT"], resource) when { principal.zone like "ops-*" };
        forbid(principal, action in [Action::"POST"], resource) when { principal.depth > 0 && resource.host == "x" };
    "#;
    let l = org(p).unwrap();
    assert_eq!(l.http, None, "permit-all");
    // The dev group's forbid applies (the box's zone is in dev), the ops-* and depth ones don't.
    assert_eq!(l.forbid.len(), 1, "{:?}", l.forbid);
    assert_eq!(l.forbid[0].hosts, vec![HostPat::Exact("prod.example.com".into())]);
    assert_eq!(l.forbid[0].methods, Some(vec!["DELETE".into()]));
    // A permit-all org policy compiles to nothing but its forbids, and a box outside dev gets none.
    let mut outside = mint();
    outside.groups.clear();
    let p = OrgPolicy::parse(p, "[]").unwrap();
    assert!(p.layer(&outside).unwrap().forbid.is_empty());
}

#[test]
fn groups_come_from_the_org_entities() {
    let ents = r#"[
      {"uid": {"type": "Zone", "id": "dev-api"}, "attrs": {}, "parents": [{"type": "Group", "id": "dev"}]},
      {"uid": {"type": "Group", "id": "dev"}, "attrs": {}, "parents": [{"type": "Group", "id": "eng"}]},
      {"uid": {"type": "Group", "id": "eng"}, "attrs": {}, "parents": []}
    ]"#;
    let p = OrgPolicy::parse("permit(principal, action, resource);", ents).unwrap();
    assert_eq!(p.groups_of("dev-api"), BTreeSet::from(["dev".to_string(), "eng".to_string()]));
    assert!(p.groups_of("other").is_empty());
    assert_ne!(
        p.version(),
        OrgPolicy::parse("permit(principal, action, resource);", "[]").unwrap().version(),
        "entities are part of the version"
    );
}

// ---- the differential test --------------------------------------------------------------------

const HOSTS: [&str; 6] = ["api.github.com", "a.githubusercontent.com", "prod.example.com", "example.com", "docs.rs", "x.internal"];
const PATHS: [&str; 8] =
    ["/", "/repos/acme/api/pulls/7", "/repos/acme/api", "/repos/other/x", "/admin/users", "/ADMIN/users", "/a/b/c", "/tokio/x"];
const GLOBS: [&str; 6] = ["/repos/acme/**", "/repos/*/x", "/admin/**", "/**", "/tokio/*", "/a/*/c"];
const LIKES: [&str; 4] = ["/admin*", "*/x", "/a/*/c", "*"];
const IMAGES: [&str; 3] = ["img:agent", "img:rust", "img:py"];
const ZONES: [&str; 3] = ["ops", "dev-api", "other"];

fn s(v: &str) -> String {
    wicket_policy::zone::lit(v)
}

/// One random org policy within the fragment (and validating strictly).
fn random_org(rng: &mut Rng) -> String {
    let mut out = vec![];
    let http_actions = |rng: &mut Rng| -> String {
        let all = wicket_policy::schema::METHODS;
        let n = 1 + rng.below(3);
        let mut ms: Vec<&str> = (0..n).map(|_| *rng.pick(&all)).collect();
        ms.sort();
        ms.dedup();
        format!("[{}]", ms.iter().map(|m| format!("Action::{}", s(m))).collect::<Vec<_>>().join(", "))
    };
    let http_atom = |rng: &mut Rng| -> String {
        match rng.below(9) {
            0 => format!("resource.host == {}", s(rng.pick(&HOSTS))),
            1 => format!("resource.host like {}", s(&format!("*{}", [".githubusercontent.com", ".com", ".internal"][rng.below(3)]))),
            2 => format!("resource.host != {}", s(rng.pick(&HOSTS))),
            3 => format!("resource.path_matches.contains({})", s(rng.pick(&GLOBS))),
            4 => format!("resource.path_matches_any_case.contains({})", s(rng.pick(&GLOBS))),
            5 => format!("resource.path like {}", s(rng.pick(&LIKES))),
            6 => format!("context.risk {} {}", ["<=", "<", ">=", ">", "==", "!="][rng.below(6)], rng.below(6)),
            7 => format!("principal.zone {}", ["== \"dev-api\"", "like \"ops*\"", "!= \"other\""][rng.below(3)]),
            _ => format!("principal in Group::{}", s(["dev", "eng"][rng.below(2)])),
        }
    };
    let cond = |rng: &mut Rng| -> String {
        let n = rng.below(4);
        if n == 0 {
            return String::new();
        }
        let parts: Vec<String> = (0..n).map(|_| http_atom(rng)).collect();
        let joined =
            if rng.chance(30) && parts.len() > 1 { format!("({}) || ({})", parts[0], parts[1..].join(" && ")) } else { parts.join(" && ") };
        format!(" {} {{ {joined} }}", if rng.chance(15) { "unless" } else { "when" })
    };
    // HTTP permits (or all), and forbids.
    if rng.chance(55) {
        out.push("permit(principal, action, resource);".to_string());
    } else {
        for _ in 0..1 + rng.below(3) {
            let a = http_actions(rng);
            let c = cond(rng);
            out.push(format!("permit(principal, action in {a}, resource){c};"));
        }
        // Spawn, message and inject: allowed outright, or narrowed.
        if rng.chance(50) {
            out.push(r#"permit(principal, action in [Action::"spawn", Action::"message", Action::"inject"], resource);"#.into());
        } else {
            let img = rng.pick(&IMAGES);
            out.push(format!(
                r#"permit(principal, action == Action::"spawn", resource) when {{ resource in [Image::{}] && context.memory <= {} && context.isolation >= 2 }};"#,
                s(img),
                [1 << 28, 1 << 30][rng.below(2)]
            ));
            out.push(format!(r#"permit(principal, action == Action::"message", resource == Zone::{});"#, s(rng.pick(&ZONES))));
            out.push(r#"permit(principal, action == Action::"inject", resource == Secret::"gh-app-acme") when { context.host == "api.github.com" && context.header == "Authorization" };"#.into());
        }
    }
    for _ in 0..rng.below(3) {
        let a = http_actions(rng);
        let c = cond(rng);
        out.push(format!("forbid(principal, action in {a}, resource){c};"));
    }
    out.join("\n")
}

/// What a request is, both ways.
#[derive(Clone, Debug)]
enum Req {
    Http { method: String, host: String, path: String, risk: RiskClass, inject: Option<(String, String, String)> },
    Spawn { image: String, isolation: i64, mem: i64 },
    Msg { from: String },
}

fn random_req(rng: &mut Rng, zone_globs: &[String], zone: &ZoneSpec) -> Req {
    // Half the HTTP requests hit one of the zone's own reach rules: its host, a method and a path it
    // allows (so allows, and the org layer's narrowing of them, are well sampled).
    if rng.chance(45) && !zone.reach.is_empty() {
        let r = rng.pick(&zone.reach);
        let host = r.host.replace("*.", "a.");
        let method = if r.methods.is_empty() { "GET".to_string() } else { rng.pick(&r.methods).to_ascii_uppercase() };
        let path = match r.paths.as_slice() {
            [] => "/".to_string(),
            ps => rng.pick(ps).replace("**", "q/r").replace('*', "w").replace(['{', '}'], ""),
        };
        let risks = [RiskClass::R0Read, RiskClass::R1ReadScoped, RiskClass::R2WriteReversible, RiskClass::R4ExecOrPrivilege];
        return Req::Http { method, host, path, risk: *rng.pick(&risks), inject: None };
    }
    match rng.below(10) {
        0 => Req::Spawn { image: rng.pick(&IMAGES).to_string(), isolation: [1, 2][rng.below(2)], mem: [256 << 20, 2 << 30][rng.below(2)] },
        1 => Req::Msg { from: rng.pick(&ZONES).to_string() },
        _ => {
            let risks = [
                RiskClass::R0Read,
                RiskClass::R1ReadScoped,
                RiskClass::R2WriteReversible,
                RiskClass::R3ExternalOrIrreversible,
                RiskClass::R4ExecOrPrivilege,
            ];
            let path = if rng.chance(40) && !zone_globs.is_empty() {
                rng.pick(zone_globs).replace("**", "q/r").replace('*', "w")
            } else {
                rng.pick(&PATHS).to_string()
            };
            Req::Http {
                method: rng.pick(&wicket_policy::schema::METHODS).to_string(),
                host: rng.pick(&HOSTS).to_string(),
                path,
                risk: *rng.pick(&risks),
                inject: rng.chance(20).then(|| ("api.github.com".into(), "Authorization".into(), "gh-app-acme".into())),
            }
        }
    }
}

fn regex_matches(re: &str, path: &str) -> bool {
    regex::Regex::new(re).unwrap().is_match(path)
}

/// Every glob a policy text names (for the Url's `path_matches`).
fn globs_in(texts: &[&str]) -> BTreeSet<String> {
    let re = regex::Regex::new(r#"path_matches(?:_any_case)?\.contains\("((?:[^"\\]|\\.)*)"\)"#).unwrap();
    texts.iter().flat_map(|t| re.captures_iter(t).map(|c| c[1].replace("\\\"", "\"").replace("\\\\", "\\")).collect::<Vec<_>>()).collect()
}

struct Cedar {
    org: cedar_policy::PolicySet,
    zone: cedar_policy::PolicySet,
    ents: Vec<Entity>,
    globs: BTreeSet<String>,
}

/// Cedar's decision for one layer: allowed, or denied (and whether a forbid did it).
fn layer(set: &cedar_policy::PolicySet, req: &CRequest, ents: &Entities) -> (bool, bool) {
    let r = Authorizer::new().is_authorized(req, set, ents);
    assert!(r.diagnostics().errors().next().is_none(), "evaluation errors: {:?}", r.diagnostics().errors().collect::<Vec<_>>());
    let forbade = r.diagnostics().reason().any(|id| set.policy(id).is_some_and(|p| p.effect() == cedar_policy::Effect::Forbid));
    (r.decision() == CDecision::Allow, forbade)
}

const NEEDS_GRANT: u8 = 2;
const FORBIDDEN: u8 = 1;
const ALLOW: u8 = 0;

impl Cedar {
    fn uid(t: &str, id: &str) -> EntityUid {
        EntityUid::from_str(&format!("{t}::{}", s(id))).unwrap()
    }

    /// The expected decision kind (hard org or zone denials are Forbidden; a zone that only lacks a
    /// permit for an HTTP request needs a grant), and whether the org layer alone allows the request.
    fn decide_with_org(&self, zone: &str, r: &Req) -> (u8, bool) {
        let principal = Self::uid("Box", "b0");
        let mut ents = self.ents.clone();
        let box_attrs: HashMap<String, RestrictedExpression> = [
            ("zone".to_string(), RestrictedExpression::new_string(zone.into())),
            ("tenant".to_string(), RestrictedExpression::new_string(TENANT.into())),
            ("principal".to_string(), RestrictedExpression::new_string("human:alex".into())),
            ("depth".to_string(), RestrictedExpression::new_long(0)),
        ]
        .into();
        ents.push(Entity::new(principal.clone(), box_attrs, HashSet::from([Self::uid("Zone", zone)])).unwrap());
        let one = |action: &str, resource: EntityUid, ctx: Vec<(&str, RestrictedExpression)>, ents: Vec<Entity>| -> (u8, bool) {
            let schema = wicket_policy::schema::schema();
            let ents = Entities::from_entities(ents, Some(&schema)).unwrap();
            let ctx = Context::from_pairs(ctx.into_iter().map(|(k, v)| (k.to_string(), v))).unwrap();
            let req = CRequest::new(principal.clone(), Self::uid("Action", action), resource, ctx, Some(&schema)).unwrap();
            let (org_ok, _) = layer(&self.org, &req, &ents);
            let (zone_ok, zone_forbade) = layer(&self.zone, &req, &ents);
            let k = if !org_ok || zone_forbade {
                FORBIDDEN
            } else if zone_ok {
                ALLOW
            } else {
                NEEDS_GRANT
            };
            (k, org_ok)
        };
        match r {
            Req::Http { method, host, path, risk, inject } => {
                let url = Self::uid("Url", "u");
                let set = |any_case: bool| -> RestrictedExpression {
                    let m: Vec<RestrictedExpression> = self
                        .globs
                        .iter()
                        .filter(|g| {
                            let g2 = if any_case { wicket_core::manifest::fold_case_glob(g) } else { g.to_string() };
                            regex_matches(&wicket_authz::generator::path_regex(&g2).unwrap(), path)
                        })
                        .map(|g| RestrictedExpression::new_string(g.clone()))
                        .collect();
                    RestrictedExpression::new_set(m)
                };
                let attrs: HashMap<String, RestrictedExpression> = [
                    ("host".to_string(), RestrictedExpression::new_string(host.clone())),
                    ("path".to_string(), RestrictedExpression::new_string(path.clone())),
                    ("path_matches".to_string(), set(false)),
                    ("path_matches_any_case".to_string(), set(true)),
                ]
                .into();
                let mut e = ents.clone();
                e.push(Entity::new(url.clone(), attrs, HashSet::new()).unwrap());
                let (k, org_http) = one(method, url, vec![("risk", RestrictedExpression::new_long(risk_level(*risk)))], e);
                match inject {
                    // The injection is a second decision; refusing it is hard.
                    Some((h, hd, sec)) => {
                        let mut e = ents.clone();
                        e.push(Entity::new_no_attrs(Self::uid("Secret", sec), HashSet::new()));
                        let ctx = vec![
                            ("host", RestrictedExpression::new_string(h.clone())),
                            ("header", RestrictedExpression::new_string(hd.clone())),
                        ];
                        let (ik, org_inject) = one("inject", Self::uid("Secret", sec), ctx, e);
                        (if ik != ALLOW { FORBIDDEN } else { k }, org_http && org_inject)
                    }
                    None => (k, org_http),
                }
            }
            Req::Spawn { image, isolation, mem } => {
                let mut e = ents.clone();
                e.push(Entity::new_no_attrs(Self::uid("Image", image), HashSet::new()));
                let ctx = vec![
                    ("isolation", RestrictedExpression::new_long(*isolation)),
                    ("memory", RestrictedExpression::new_long(*mem)),
                    ("cpus_milli", RestrictedExpression::new_long(250)),
                    ("pids", RestrictedExpression::new_long(64)),
                    ("timeout_s", RestrictedExpression::new_long(900)),
                ];
                let (k, org) = one("spawn", Self::uid("Image", image), ctx, e);
                (if k == NEEDS_GRANT { FORBIDDEN } else { k }, org)
            }
            Req::Msg { from } => {
                let mut e = ents.clone();
                if !e.iter().any(|x| x.uid() == Self::uid("Zone", from)) {
                    e.push(Entity::new_no_attrs(Self::uid("Zone", from), HashSet::new()));
                }
                let (k, org) = one("message", Self::uid("Zone", from), vec![], e);
                (if k == NEEDS_GRANT { FORBIDDEN } else { k }, org)
            }
        }
    }
}

fn token_request(r: &Req) -> Request {
    let action = match r {
        Req::Http { method, host, path, risk, inject } => Action::Http {
            host: host.clone(),
            method: method.clone(),
            path: path.clone(),
            risk: *risk,
            inject: inject.as_ref().map(|(h, hd, s)| format!("{h}|{hd}|{s}")),
        },
        Req::Spawn { image, isolation, mem } => {
            Action::Spawn { image: image.clone(), isolation: *isolation, mem_bytes: *mem, cpus_milli: 250, pids: 64, timeout_s: 900 }
        }
        Req::Msg { from } => Action::Msg { from: from.clone() },
    };
    Request { time: T0 + 60, tenant: TENANT.into(), box_id: "b0".into(), epoch: 1, action, uses_left: vec![] }
}

fn kind(d: &Decision) -> u8 {
    match d {
        Decision::Allow => ALLOW,
        Decision::Forbidden(_) => FORBIDDEN,
        Decision::NeedsGrant(_) => NEEDS_GRANT,
    }
}

/// The example zones, a small spawn-capable one, and random org policies: Cedar and the token agree.
#[test]
fn cedar_and_the_compiled_token_agree() {
    let keys = Keys::new(0);
    let ents = r#"[
      {"uid": {"type": "Zone", "id": "dev-api"}, "attrs": {}, "parents": [{"type": "Group", "id": "dev"}]},
      {"uid": {"type": "Group", "id": "dev"}, "attrs": {}, "parents": [{"type": "Group", "id": "eng"}]},
      {"uid": {"type": "Group", "id": "eng"}, "attrs": {}, "parents": []}
    ]"#;
    let mut zones: Vec<ZoneSpec> = common::example_zones();
    zones.push(
        serde_yaml::from_str(
            "name: dev-api\nreach:\n  - { host: api.github.com, methods: [GET, PUT, POST], paths: ['/repos/acme/**'] }\n  - { host: '*.githubusercontent.com', methods: [GET] }\n  - { host: example.com, methods: [GET, DELETE], paths: ['/admin/**'], allow_dangerous: true }\nforbid:\n  - { host: api.github.com, paths: ['/admin/**'] }\ninject:\n  - { host: api.github.com, header: Authorization, format: 'Bearer {secret}', secret: gh-app-acme }\nimages: [img:rust]\naccept_from: [ops]\nlimits: { memory: 1g, cpus: 1, timeout: 1h }\n",
        )
        .unwrap(),
    );
    let mut rng = Rng(51);
    let (mut checked, mut kinds, mut refused, mut granted) = (0usize, [0usize; 3], 0usize, 0usize);
    for round in 0..160 {
        let text = random_org(&mut rng);
        let org = OrgPolicy::parse(&text, ents).unwrap_or_else(|e| panic!("round {round}: {e}\n{text}"));
        // A policy outside the fragment (a negated path, say) is refused at compile: never minted.
        if let Err(e) = org.layer(&MintCtx {
            zone: "x".into(),
            tenant: TENANT.into(),
            principal: "human:alex".into(),
            depth: 0,
            groups: BTreeSet::new(),
        }) {
            assert!(matches!(e, wicket_policy::CompileError::Unsupported { .. }), "{e}");
            refused += 1;
            continue;
        }
        for z in &zones {
            let base = Ceiling::from_zone(z, "b0", T0 + 3600, vec![keys.approver.public()]).unwrap();
            let (zone_text, _) = wicket_policy::zone_layer(z, &base).unwrap();
            let m = MintCtx {
                zone: z.name.clone(),
                tenant: TENANT.into(),
                principal: "human:alex".into(),
                depth: 0,
                groups: org.groups_of(&z.name),
            };
            let c = wicket_policy::ceiling(z, "b0", T0 + 3600, vec![keys.approver.public()], &[], Some(org.layer(&m).unwrap())).unwrap();
            let token = wicket_authz::mint(&keys.root, TENANT, "human:alex", &c).unwrap();
            let loaded = load(&token.to_bytes().unwrap(), &keys.root.public(), &|_| false).unwrap_or_else(|e| panic!("{e}\n{text}"));
            let cedar = Cedar {
                org: org.policy_set().clone(),
                zone: compile::parse(&zone_text).unwrap(),
                ents: org.entities().iter().cloned().collect(),
                globs: globs_in(&[&text, &zone_text]),
            };
            let zone_globs: Vec<String> = z.reach.iter().flat_map(|r| r.paths.clone()).collect();
            for _ in 0..12 {
                let r = random_req(&mut rng, &zone_globs, z);
                let (want, org_ok) = cedar.decide_with_org(&z.name, &r);
                let got = kind(&loaded.decide(&token_request(&r)));
                assert_eq!(got, want, "zone {}, {r:?}\norg policy:\n{text}\ndecision: {:?}", z.name, loaded.decide(&token_request(&r)));
                // The control host's own evaluator of the org layer agrees with Cedar too.
                let layer = c.org.as_ref().expect("an org layer");
                let ir_ok = match &r {
                    Req::Http { method, host, path, risk, inject } => {
                        layer.refuses_http(host, method, path, risk_level(*risk)).is_none()
                            && inject.as_ref().is_none_or(|(h, hd, s)| layer.allows_inject(&format!("{h}|{hd}|{s}")))
                    }
                    Req::Spawn { image, isolation, mem } => layer.allows_spawn(image, *isolation, *mem, 250, 64, 900),
                    Req::Msg { from } => layer.allows_message_from(from),
                };
                assert_eq!(ir_ok, org_ok, "the org IR evaluator: zone {}, {r:?}\norg policy:\n{text}", z.name);
                kinds[want as usize] += 1;
                checked += 1;
                // A grant for exactly a request that needs one: then it's allowed, unless the org
                // layer or a forbid refuses it (Forbidden whatever the grant).
                if let (NEEDS_GRANT, Req::Http { method, host, path, risk, inject: None }) = (want, &r) {
                    if rng.chance(50) {
                        let g = Grant {
                            gid: format!("g-{checked}"),
                            box_id: "b0".into(),
                            epoch: 1,
                            host: host.clone(),
                            method: method.clone(),
                            path: path.clone(),
                            not_after: T0 + 3600,
                            approver: "human:alex".into(),
                            digest: vec![1, 2, 3, 4],
                        };
                        let gt = wicket_authz::grant(&token, &keys.approver, &g).unwrap();
                        let gl = load(&gt.to_bytes().unwrap(), &keys.root.public(), &|_| false).unwrap();
                        let mut req = token_request(&r);
                        req.uses_left = vec![(g.gid.clone(), 1)];
                        let _ = risk;
                        assert_eq!(kind(&gl.decide(&req)), ALLOW, "a grant lifts the zone layer: zone {}, {r:?}\n{text}", z.name);
                        granted += 1;
                    }
                }
                if let (FORBIDDEN, Req::Http { method, host, path, inject: None, .. }) = (want, &r) {
                    if rng.chance(30) {
                        let g = Grant {
                            gid: format!("g-{checked}"),
                            box_id: "b0".into(),
                            epoch: 1,
                            host: host.clone(),
                            method: method.clone(),
                            path: path.clone(),
                            not_after: T0 + 3600,
                            approver: "human:alex".into(),
                            digest: vec![1, 2, 3, 4],
                        };
                        let gt = wicket_authz::grant(&token, &keys.approver, &g).unwrap();
                        let gl = load(&gt.to_bytes().unwrap(), &keys.root.public(), &|_| false).unwrap();
                        let mut req = token_request(&r);
                        req.uses_left = vec![(g.gid.clone(), 1)];
                        assert_eq!(kind(&gl.decide(&req)), FORBIDDEN, "no grant lifts a hard refusal: zone {}, {r:?}\n{text}", z.name);
                        granted += 1;
                    }
                }
            }
        }
    }
    eprintln!(
        "{checked} decisions agree: {} allow, {} forbidden, {} needs-grant; {refused} policies refused at compile",
        kinds[0], kinds[1], kinds[2]
    );
    assert!(refused < 40, "most generated policies compile ({refused} refused)");
    eprintln!("{granted} granted requests checked");
    assert!(kinds.iter().all(|&k| k > 400), "every outcome well exercised: {kinds:?}");
    assert!(granted > 200, "grants exercised: {granted}");
}

/// Nothing on a node evaluates Cedar: the crates a node runs on don't depend on it (Cargo.lock).
#[test]
fn nodes_dont_depend_on_cedar() {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock")).unwrap();
    let mut deps: HashMap<String, Vec<String>> = HashMap::new();
    for pkg in lock.split("[[package]]").skip(1) {
        let name = pkg.lines().find_map(|l| l.strip_prefix("name = \"")).map(|n| n.trim_end_matches('"').to_string()).unwrap();
        let ds: Vec<String> = pkg
            .split("dependencies = [")
            .nth(1)
            .map(|d| {
                d.split(']')
                    .next()
                    .unwrap_or("")
                    .lines()
                    .filter_map(|l| l.trim().strip_prefix('"'))
                    .map(|l| l.split([' ', '"']).next().unwrap().to_string())
                    .collect()
            })
            .unwrap_or_default();
        deps.entry(name).or_default().extend(ds);
    }
    for root in ["wicket-core", "wicket-authz", "wicket-feed"] {
        let mut seen = HashSet::new();
        let mut todo = vec![root.to_string()];
        while let Some(n) = todo.pop() {
            if seen.insert(n.clone()) {
                todo.extend(deps.get(&n).cloned().unwrap_or_default());
            }
        }
        for bad in ["cedar-policy", "cedar-policy-core", "wicket-policy"] {
            assert!(!seen.contains(bad), "{root} depends on {bad}");
        }
        assert!(seen.len() > 3, "{root}: the lock file was read ({} crates)", seen.len());
    }
}

/// The example org policy (docs/reference/policy.md) compiles, and does what the docs say.
#[test]
fn the_example_org_policy_compiles_as_documented() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples/policy");
    let p = OrgPolicy::parse(
        &std::fs::read_to_string(format!("{dir}/org.cedar")).unwrap(),
        &std::fs::read_to_string(format!("{dir}/org-entities.json")).unwrap(),
    )
    .unwrap();
    let dev =
        MintCtx { zone: "dev-api".into(), tenant: TENANT.into(), principal: "human:alex".into(), depth: 0, groups: p.groups_of("dev-api") };
    let other = MintCtx { zone: "ops".into(), groups: p.groups_of("ops"), ..dev.clone() };
    let (ld, lo) = (p.layer(&dev).unwrap(), p.layer(&other).unwrap());
    // HTTP isn't narrowed beyond the forbids; a dev zone has one forbid more.
    assert_eq!((ld.http.as_ref(), lo.http.as_ref()), (None, None));
    assert_eq!(ld.forbid.len(), lo.forbid.len() + 1);
    // Spawns: gVisor, under 2 GiB.
    let s = &ld.spawn.as_ref().unwrap()[0];
    assert_eq!((s.min_isolation, s.max_mem_bytes), (Some(2), Some(2 << 30)));
}
