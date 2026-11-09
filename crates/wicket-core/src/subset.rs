//! Authority only narrows (design principle 5). A zone an agent constructs for a box it starts must be
//! a subset of the agent's own: wicket proves it before starting anything, conservatively. Anything
//! it can't prove contained counts as not contained, and every violation is reported, so the agent
//! can narrow its request or ask a human for the difference (request_access).

use crate::manifest::{host_matches, Isolation, UnlistedHosts, ZoneSpec};
use std::time::Duration;

/// What the constructing agent has: its zone and what's left of its budgets.
pub struct Bounds<'a> {
    pub zone: &'a ZoneSpec,
    /// Images it may start boxes from (its own, plus its zone's `images`).
    pub images: Vec<String>,
    /// Model requests and output tokens it has left.
    pub llm_remaining: Option<(u64, u64)>,
    pub time_remaining: Duration,
    /// How many more boxes it may start.
    pub child_slots: u32,
}

/// The parts of a request that aren't in the zone itself.
pub struct Ask<'a> {
    pub zone: &'a ZoneSpec,
    pub image: &'a str,
    pub max_children: u32,
}

pub fn check(ask: &Ask<'_>, parent: &Bounds<'_>) -> Result<(), Vec<String>> {
    let (c, p) = (ask.zone, parent.zone);
    let mut v = Vec::new();

    if strength(c.isolation) < strength(p.isolation) {
        v.push(format!("isolation {:?} is weaker than this zone's {:?}", c.isolation, p.isolation));
    }
    if p.unlisted_hosts == UnlistedHosts::Hide && c.unlisted_hosts != UnlistedHosts::Hide {
        v.push("unlisted_hosts must be hide, as in this zone".into());
    }
    for (i, r) in c.reach.iter().enumerate() {
        for m in &r.methods {
            for path in &r.paths {
                let covered = p.reach.iter().any(|q| {
                    host_covers(&q.host, &r.host)
                        && q.methods.iter().any(|qm| qm.eq_ignore_ascii_case(m))
                        && path_covered(&q.paths, path)
                        && (!r.allow_dangerous || q.allow_dangerous)
                });
                if !covered {
                    v.push(format!("reach rule {i}: {m} {}{path} is not within this zone's reach{}", r.host, if r.allow_dangerous { " (with allow_dangerous)" } else { "" }));
                }
            }
        }
    }
    for i in &c.inject {
        let same = p.inject.iter().any(|q| q.host == i.host && q.header == i.header && q.format == i.format && q.secret == i.secret);
        if !same {
            v.push(format!("inject {} {}: only this zone's own credential injections can be passed on", i.host, i.header));
        }
    }
    match (&c.llm, &p.llm) {
        (None, _) => {}
        (Some(_), None) => v.push("a model route: this zone has none".into()),
        (Some(cl), Some(pl)) => {
            if cl.provider != pl.provider || cl.secret != pl.secret || cl.upstream != pl.upstream {
                v.push("the model route must be this zone's own (same provider, credential and upstream)".into());
            }
            if cl.allow_server_tools && !pl.allow_server_tools {
                v.push("server-side model tools: this zone doesn't allow them".into());
            }
            if let Some((reqs, toks)) = parent.llm_remaining {
                if cl.max_requests > reqs {
                    v.push(format!("{} model requests: only {reqs} are left in this zone's budget", cl.max_requests));
                }
                if cl.max_output_tokens > toks {
                    v.push(format!("{} output tokens: only {toks} are left in this zone's budget", cl.max_output_tokens));
                }
            }
        }
    }
    match (parse_bytes(&c.limits.memory), parse_bytes(&p.limits.memory)) {
        (Some(cm), Some(pm)) if cm <= pm => {}
        _ => v.push(format!("memory {}: more than this zone's {} (or unreadable)", c.limits.memory, p.limits.memory)),
    }
    if c.limits.cpus > p.limits.cpus {
        v.push(format!("cpus {}: more than this zone's {}", c.limits.cpus, p.limits.cpus));
    }
    if c.limits.pids > p.limits.pids {
        v.push(format!("pids {}: more than this zone's {}", c.limits.pids, p.limits.pids));
    }
    match c.limits.timeout() {
        Ok(t) if t <= parent.time_remaining => {}
        _ => v.push(format!("timeout {}: more than the {}s this zone has left", c.limits.timeout, parent.time_remaining.as_secs())),
    }
    if !parent.images.iter().any(|i| i == ask.image) {
        v.push(format!("image {}: not one this zone may start (allowed: {})", ask.image, parent.images.join(", ")));
    }
    for i in &c.images {
        if !parent.images.contains(i) {
            v.push(format!("images: {i} is not one this zone may start"));
        }
    }
    for z in &c.accept_from {
        if z != &p.name && !p.accept_from.contains(z) {
            v.push(format!("accept_from {z}: this zone doesn't accept messages from it either"));
        }
    }
    if ask.max_children >= parent.child_slots {
        v.push(format!("max_children {}: this zone has {} box(es) left to start, including this one", ask.max_children, parent.child_slots));
    }
    if v.is_empty() {
        Ok(())
    } else {
        Err(v)
    }
}

fn strength(i: Isolation) -> u8 {
    match i {
        Isolation::Runc => 1,
        Isolation::Gvisor => 2,
    }
}

/// Whether every host `child` names is matched by `parent`.
fn host_covers(parent: &str, child: &str) -> bool {
    let (p, c) = (parent.to_ascii_lowercase(), child.to_ascii_lowercase());
    match (p.strip_prefix("*."), c.strip_prefix("*.")) {
        (_, None) => host_matches(&p, &c),
        (Some(ps), Some(cs)) => cs == ps || cs.ends_with(&format!(".{ps}")),
        (None, Some(_)) => false,
    }
}

/// Whether every path `child` (a glob) matches is matched by one of `parent` (globs). Proven three
/// ways: the same glob; a literal path the parent matches; or a parent `Q/**` (or `/**`) that the
/// child's literal prefix lies under. Anything else is unproven, so not covered.
fn path_covered(parent: &[String], child: &str) -> bool {
    if parent.iter().any(|g| g == child || g == "/**") {
        return true;
    }
    let wild = child.find(['*', '?', '[', '{']);
    let literal = &child[..wild.unwrap_or(child.len())];
    if wild.is_none() {
        return parent.iter().any(|g| crate::manifest::compile_glob(g).map(|m| m.is_match(child)).unwrap_or(false));
    }
    parent.iter().any(|g| match g.strip_suffix("/**") {
        Some(q) if !q.contains(['*', '?', '[', '{']) => literal.starts_with(&format!("{q}/")),
        _ => false,
    })
}

/// "1500m", "2g", "512M", "1G", "1048576" → bytes.
pub fn parse_bytes(s: &str) -> Option<u64> {
    let s = s.trim().to_ascii_lowercase();
    let (num, mult) = match s.chars().last()? {
        'k' => (&s[..s.len() - 1], 1u64 << 10),
        'm' => (&s[..s.len() - 1], 1 << 20),
        'g' => (&s[..s.len() - 1], 1 << 30),
        'b' => (&s[..s.len() - 1], 1),
        _ => (&s[..], 1),
    };
    num.trim().parse::<f64>().ok().filter(|n| *n >= 0.0).map(|n| (n * mult as f64) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Manifest;

    fn zone(body: &str) -> ZoneSpec {
        let llm = if body.contains("  llm:") { "" } else { "  llm: {}\n" };
        Manifest::from_yaml(&format!("task: t\nagent: {{ name: a }}\nzone:\n  name: z\n{llm}{body}")).unwrap().zone
    }

    fn parent() -> ZoneSpec {
        zone("  reach:\n    - { host: api.github.com, paths: [\"/repos/acme/**\"] }\n    - { host: \"*.example.com\", methods: [GET, HEAD, POST] }\n    - { host: docs.rs, paths: [\"/tokio/*\"] }\n  inject: [{ host: api.github.com, header: Authorization, format: \"Bearer {secret}\", secret: gh }]\n  limits: { memory: 2g, cpus: 2, timeout: 1h }\n  accept_from: [ops]\n")
    }

    fn bounds(z: &ZoneSpec) -> Bounds<'_> {
        Bounds { zone: z, images: vec!["img:a".into(), "img:b".into()], llm_remaining: Some((100, 50_000)), time_remaining: Duration::from_secs(1800), child_slots: 3 }
    }

    fn ask<'a>(z: &'a ZoneSpec) -> Ask<'a> {
        Ask { zone: z, image: "img:b", max_children: 0 }
    }

    #[test]
    fn a_narrower_zone_passes() {
        let p = parent();
        let c = zone("  reach:\n    - { host: api.github.com, paths: [\"/repos/acme/api/**\", \"/repos/acme/api\"] }\n    - { host: www.example.com }\n    - { host: \"*.cdn.example.com\" }\n    - { host: docs.rs, paths: [\"/tokio/latest\"] }\n  inject: [{ host: api.github.com, header: Authorization, format: \"Bearer {secret}\", secret: gh }]\n  llm: { max_requests: 40, max_output_tokens: 20000 }\n  limits: { memory: 1500m, cpus: 1, timeout: 20m }\n  accept_from: [z, ops]\n");
        assert_eq!(check(&ask(&c), &bounds(&p)), Ok(()));
    }

    #[test]
    fn every_widening_is_named() {
        let p = parent();
        let c = zone("  isolation: runc\n  reach:\n    - { host: api.github.com, methods: [PUT], paths: [\"/repos/acme/**\"] }\n    - { host: api.github.com, paths: [\"/repos/other/**\"] }\n    - { host: \"*.com\" }\n    - { host: docs.rs, paths: [\"/tokio/**\"] }\n    - { host: example.com }\n  inject: [{ host: api.github.com, header: Authorization, format: \"Bearer {secret}\", secret: admin-token }]\n  llm: { max_requests: 500, secret: other }\n  limits: { memory: 4g, cpus: 4, timeout: 2h }\n  images: [img:root]\n  accept_from: [anyone]\n");
        let mut a = ask(&c);
        a.image = "img:root";
        a.max_children = 5;
        let errs = check(&a, &bounds(&p)).unwrap_err().join("\n");
        for needle in [
            "isolation", "PUT api.github.com/repos/acme/**", "/repos/other/**", "*.com", "docs.rs/tokio/**", "example.com/**",
            "credential injections", "model route must be", "500 model requests", "memory 4g", "cpus 4", "timeout 2h",
            "image img:root", "images: img:root", "accept_from anyone", "max_children 5",
        ] {
            assert!(errs.contains(needle), "missing {needle:?} in:\n{errs}");
        }
    }

    #[test]
    fn hidden_hosts_stay_hidden() {
        let p = zone("  unlisted_hosts: hide\n");
        let c = zone("");
        assert!(check(&ask(&c), &Bounds { zone: &p, ..bounds(&p) }).unwrap_err()[0].contains("hide"));
    }

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_bytes("1500m"), Some(1500 << 20));
        assert_eq!(parse_bytes("2G"), Some(2 << 30));
        assert_eq!(parse_bytes("lots"), None);
    }
}
