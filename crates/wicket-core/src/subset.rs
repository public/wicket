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
    /// Input tokens it has left, cached ones included, if its zone caps them.
    pub llm_input_remaining: Option<u64>,
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
    v.extend(reach_violations(p, c));
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
            // A capped zone can't start an uncapped child, or one with more input than it has left.
            match (cl.max_input_tokens, parent.llm_input_remaining) {
                (_, None) => {}
                (None, Some(left)) => v.push(format!("no input token cap: this zone caps input tokens, and has {left} left")),
                (Some(c), Some(left)) if c > left => v.push(format!("{c} input tokens: only {left} are left in this zone's budget")),
                (Some(_), Some(_)) => {}
            }
        }
    }
    // Every limit is between a floor of 1 and the parent's own (#126): Docker reads 0 as no limit,
    // so 0 is never within a finite parent. Written so that NaN or an unreadable value fails.
    match (parse_bytes(&c.limits.memory), parse_bytes(&p.limits.memory)) {
        (Some(cm), Some(pm)) if cm >= 1 && cm <= pm => {}
        _ => v.push(format!("memory {}: more than this zone's {} (or zero, or unreadable)", c.limits.memory, p.limits.memory)),
    }
    let (cc, pc) = (c.limits.cpus, p.limits.cpus);
    if !(cc.is_finite() && cc >= crate::manifest::MIN_CPUS && cc <= pc) {
        v.push(format!("cpus {cc}: more than this zone's {pc} (or below {})", crate::manifest::MIN_CPUS));
    }
    match (parse_bytes(&c.limits.output), parse_bytes(&p.limits.output)) {
        (Some(c), Some(p)) if c >= 1 && c <= p => {}
        _ => v.push(format!("output {}: more than this zone's {} (or zero, or unreadable)", c.limits.output, p.limits.output)),
    }
    if c.limits.on_output_full != p.limits.on_output_full && p.limits.on_output_full == crate::manifest::OnOutputFull::Stop {
        v.push("on_output_full: this zone stops a box whose output is full; a child can't keep going".into());
    }
    if !(c.limits.pids >= 1 && c.limits.pids <= p.limits.pids) {
        v.push(format!("pids {}: more than this zone's {} (or zero)", c.limits.pids, p.limits.pids));
    }
    match c.limits.timeout() {
        Ok(t) if !t.is_zero() && t <= parent.time_remaining => {}
        _ => {
            v.push(format!("timeout {}: more than the {}s this zone has left (or zero)", c.limits.timeout, parent.time_remaining.as_secs()))
        }
    }
    // A child's authority (#153) is its own token's block, attenuated from its parent's: it can't
    // outlast the parent's, whatever it says, but one that asks for more is refused here too.
    match (c.limits.authority(), p.limits.authority()) {
        (Ok(ca), Ok(pa)) if ca <= pa => {}
        _ => v.push(format!(
            "authority {}: longer than this zone's {} (or unreadable)",
            c.limits.authority.as_deref().unwrap_or(&c.limits.timeout),
            p.limits.authority.as_deref().unwrap_or(&p.limits.timeout)
        )),
    }
    // By digest where either side is pinned (#192): one matcher, wherever a spawn is decided.
    if crate::image::matching(ask.image, &parent.images).is_none() {
        v.push(format!("image {}: not one this zone may start (allowed: {})", ask.image, parent.images.join(", ")));
    }
    for i in &c.images {
        if crate::image::matching(i, &parent.images).is_none() {
            v.push(format!("images: {i} is not one this zone may start"));
        }
    }
    for z in &c.accept_from {
        if z != &p.name && !p.accept_from.contains(z) {
            v.push(format!("accept_from {z}: this zone doesn't accept messages from it either"));
        }
    }
    if ask.max_children >= parent.child_slots {
        v.push(format!(
            "max_children {}: this zone has {} box(es) left to start, including this one",
            ask.max_children, parent.child_slots
        ));
    }
    if v.is_empty() {
        Ok(())
    } else {
        Err(v)
    }
}

/// What no human approval may widen in a spawned zone (#118): the model route (provider, credential
/// and upstream) must be the parent's own, and every credential injection one the parent makes to
/// the same host, header and format. A card can't show a human what sending the model token, or a
/// vault secret, to a URL the agent picked would mean, so these are refused outright. Each entry
/// names exactly what the child asked for.
pub fn unapprovable(child: &ZoneSpec, parent: &ZoneSpec) -> Vec<String> {
    let mut v = Vec::new();
    match (&child.llm, &parent.llm) {
        (Some(cl), Some(pl)) if cl.provider != pl.provider || cl.secret != pl.secret || cl.upstream != pl.upstream => v.push(format!(
            "the model route must be this zone's own: asked for provider {}, secret {}, upstream {}; this zone's is {}, {}, {}",
            cl.provider, cl.secret, cl.upstream, pl.provider, pl.secret, pl.upstream
        )),
        _ => {}
    }
    for i in &child.inject {
        let same = parent.inject.iter().any(|q| q.host == i.host && q.header == i.header && q.format == i.format && q.secret == i.secret);
        if !same {
            v.push(format!(
                "inject secret {} into {} {}: only this zone's own credential injections can be passed on",
                i.secret, i.host, i.header
            ));
        }
    }
    v
}

/// Whether `inner`'s reach is within `outer`'s: every reach rule covered, every forbid rule kept,
/// no credential injection or model route `outer` lacks, and no unlisted hosts shown that `outer`
/// hides. This is the authority a box lends whoever is linked to it (design §4.3): a connector may
/// only reach a box whose zone could do nothing the connector's own zone couldn't. Conservative, as
/// [`check`] is.
pub fn reach_within(outer: &ZoneSpec, inner: &ZoneSpec) -> Result<(), Vec<String>> {
    let mut v = reach_violations(outer, inner);
    if inner.llm.is_some() && outer.llm.is_none() {
        v.push("a model route: this zone has none".into());
    }
    if v.is_empty() {
        Ok(())
    } else {
        Err(v)
    }
}

/// The reach, forbid, credential and unlisted-host parts of [`check`].
fn reach_violations(p: &ZoneSpec, c: &ZoneSpec) -> Vec<String> {
    let mut v = Vec::new();
    if p.unlisted_hosts == UnlistedHosts::Hide && c.unlisted_hosts != UnlistedHosts::Hide {
        v.push("unlisted_hosts must be hide, as in this zone".into());
    }
    if p.wildcards.forbid && !c.wildcards.forbid {
        v.push("wildcards.forbid must be true, as in this zone".into());
    }
    if c.wildcards.max_names > p.wildcards.max_names {
        v.push(format!("wildcards.max_names {} is more than this zone's {}", c.wildcards.max_names, p.wildcards.max_names));
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
                    v.push(format!(
                        "reach rule {i}: {m} {}{path} is not within this zone's reach{}",
                        r.host,
                        if r.allow_dangerous { " (with allow_dangerous)" } else { "" }
                    ));
                }
            }
        }
    }
    // The parent's forbid rules bind the child too: each forbidden path must stay forbidden, by a child
    // forbid rule with the same or a wider host (the paths of one parent rule may be split across
    // several child rules).
    for (i, f) in p.forbid.iter().enumerate() {
        let kept = f.paths.iter().all(|fp| c.forbid.iter().any(|g| host_covers(&g.host, &f.host) && path_covered(&g.paths, fp)));
        if !kept {
            v.push(format!("forbid rule {i} ({} {}) of this zone must be kept", f.host, f.paths.join(", ")));
        }
    }
    for i in &c.inject {
        let same = p.inject.iter().any(|q| q.host == i.host && q.header == i.header && q.format == i.format && q.secret == i.secret);
        if !same {
            v.push(format!("inject {} {}: only this zone's own credential injections can be passed on", i.host, i.header));
        }
    }
    v
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

/// Whether every path `child` (a glob) matches is matched by one of `parent` (globs). Proven by: the
/// same glob; a literal path a parent glob matches; a parent `Q/**` (literal `Q`) that the child's
/// literal prefix lies under; or segment by segment (`segments_cover`). Anything else is unproven, so
/// not covered: this check may refuse a narrower zone, but never accepts a wider one.
fn path_covered(parent: &[String], child: &str) -> bool {
    if parent.iter().any(|g| g == child || g == "/**") {
        return true;
    }
    let wild = child.find(META);
    if wild.is_none() {
        return parent.iter().any(|g| crate::manifest::compile_glob(g).map(|m| m.is_match(child)).unwrap_or(false));
    }
    let literal = &child[..wild.unwrap_or(child.len())];
    parent.iter().any(|g| match g.strip_suffix("/**") {
        Some(q) if !q.contains(META) && literal.starts_with(&format!("{q}/")) => true,
        _ => segments_cover(g, child),
    })
}

/// Glob metacharacters (and `\`, which escapes them).
const META: [char; 5] = ['*', '?', '[', '{', '\\'];

/// One element of a path glob split at `/`, under the matcher's semantics (`literal_separator`):
/// a `**` segment matches any number of segments (at least one at the end of a glob, where `/a/**`
/// doesn't match `/a`); any other segment matches exactly one segment, and its `*` stops at `/`.
#[derive(Clone, Copy, PartialEq)]
enum Seg<'a> {
    Any,
    One(&'a str),
}

/// Splits an absolute glob into segments. `None` if it isn't one this proof handles: not absolute, or
/// a `{…}` or `[…]` group that contains `/`, which splitting at `/` would cut in two.
fn segments(glob: &str) -> Option<Vec<Seg<'_>>> {
    let body = glob.strip_prefix('/')?;
    let (mut depth, mut class) = (0i32, false);
    for ch in body.chars() {
        match ch {
            '{' if !class => depth += 1,
            '}' if !class => depth -= 1,
            '[' => class = true,
            ']' => class = false,
            '/' if depth != 0 || class => return None,
            _ => {}
        }
    }
    Some(body.split('/').map(|s| if s == "**" { Seg::Any } else { Seg::One(s) }).collect())
}

/// Whether every path the glob `child` matches is matched by the glob `parent`, compared segment by
/// segment. Sound but not complete: a child segment with wildcards is covered only by the same text
/// or by `*`.
fn segments_cover(parent: &str, child: &str) -> bool {
    let (Some(p), Some(c)) = (segments(parent), segments(child)) else { return false };
    // ok[i][j]: parent segments i.. cover child segments j..
    let mut ok = vec![vec![false; c.len() + 1]; p.len() + 1];
    ok[p.len()][c.len()] = true;
    for i in (0..p.len()).rev() {
        for j in (0..=c.len()).rev() {
            ok[i][j] = match p[i] {
                // A trailing `**` matches one or more segments, so it covers any non-empty rest: that
                // rest ends in a segment or in a trailing `**`, either of which is at least one segment.
                Seg::Any if i + 1 == p.len() => j < c.len(),
                // Elsewhere `**` matches zero or more: skip it, or let it absorb the next child element.
                Seg::Any => ok[i + 1][j] || (j < c.len() && ok[i][j + 1]),
                Seg::One(ps) => match c.get(j) {
                    Some(Seg::One(cs)) => segment_covers(ps, cs) && ok[i + 1][j + 1],
                    // One parent segment can't cover a child `**` (any number of segments).
                    Some(Seg::Any) | None => false,
                },
            };
        }
    }
    ok[0][0]
}

/// Whether every segment the pattern `child` matches is matched by the pattern `parent`.
///
/// A class (`[!z]`, `[.-0]`) can match `/` even with `literal_separator`, and an escape or a brace
/// can hide one, so a child segment with `[`, `{` or `\` may span several segments: only the same
/// text proves it covered (#111). A parent `*` covers child segments made of literals, `*` and `?`,
/// none of which match `/`.
fn segment_covers(parent: &str, child: &str) -> bool {
    if parent == child {
        return true;
    }
    if child.contains(['[', '{', '\\']) {
        return false;
    }
    if parent == "*" {
        return true;
    }
    if child.contains(META) {
        return false;
    }
    crate::manifest::compile_glob(parent).map(|m| m.is_match(child)).unwrap_or(false)
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
        Bounds {
            llm_input_remaining: None,
            zone: z,
            images: vec!["img:a".into(), "img:b".into()],
            llm_remaining: Some((100, 50_000)),
            time_remaining: Duration::from_secs(1800),
            child_slots: 3,
        }
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
            "isolation",
            "PUT api.github.com/repos/acme/**",
            "/repos/other/**",
            "*.com",
            "docs.rs/tokio/**",
            "example.com/**",
            "credential injections",
            "model route must be",
            "500 model requests",
            "memory 4g",
            "cpus 4",
            "timeout 2h",
            "image img:root",
            "images: img:root",
            "accept_from anyone",
            "max_children 5",
        ] {
            assert!(errs.contains(needle), "missing {needle:?} in:\n{errs}");
        }
    }

    /// #20: a zone that forbids wildcards binds its children, and a child may not reach more names
    /// under a wildcard than its parent.
    #[test]
    fn a_zone_forbidding_wildcards_binds_its_children() {
        let p = zone("  wildcards: { forbid: true, max_names: 8 }\n  reach: [{ host: api.example.com }]\n");
        let errs = check(&ask(&zone("")), &Bounds { zone: &p, ..bounds(&p) }).unwrap_err().join("\n");
        assert!(errs.contains("wildcards.forbid must be true") && errs.contains("max_names 32 is more than this zone's 8"), "{errs}");
        let ok = zone("  llm: { max_requests: 10, max_output_tokens: 1000 }\n  wildcards: { forbid: true, max_names: 4 }\n  reach: [{ host: api.example.com }]\n");
        let r = check(&ask(&ok), &Bounds { zone: &p, ..bounds(&p) });
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn hidden_hosts_stay_hidden() {
        let p = zone("  unlisted_hosts: hide\n");
        let c = zone("");
        assert!(check(&ask(&c), &Bounds { zone: &p, ..bounds(&p) }).unwrap_err()[0].contains("hide"));
    }

    #[test]
    fn forbid_rules_must_be_kept() {
        let p = zone("  reach:\n    - { host: api.example.com, methods: [GET, POST], paths: [\"/**\"] }\n  forbid:\n    - { host: api.example.com, paths: [\"/private/**\"] }\n    - { host: mcp.example.com }\n  limits: { memory: 2g, cpus: 1, timeout: 1h }\n");
        let reach = "  reach:\n    - { host: api.example.com, methods: [GET], paths: [\"/**\"] }\n  limits: { memory: 1g, cpus: 1, timeout: 10m }\n  llm: { max_requests: 10, max_output_tokens: 1000 }\n";
        let dropped = zone(reach);
        let errs = check(&ask(&dropped), &bounds(&p)).unwrap_err().join("\n");
        assert!(errs.contains("forbid rule 0 (api.example.com /private/**)"), "{errs}");
        assert!(errs.contains("forbid rule 1 (mcp.example.com /**)"), "{errs}");
        let narrower = zone(&format!(
            "{reach}  forbid:\n    - {{ host: api.example.com, paths: [\"/private/x\"] }}\n    - {{ host: mcp.example.com }}\n"
        ));
        assert!(check(&ask(&narrower), &bounds(&p)).unwrap_err()[0].contains("forbid rule 0"));
        let kept = zone(&format!(
            "{reach}  forbid:\n    - {{ host: api.example.com, paths: [\"/private/**\"] }}\n    - {{ host: mcp.example.com }}\n"
        ));
        assert_eq!(check(&ask(&kept), &bounds(&p)), Ok(()));
        // One parent rule with two paths, kept by two child rules; dropping either path is refused.
        let two = zone("  reach:\n    - { host: api.example.com, methods: [GET], paths: [\"/**\"] }\n  forbid:\n    - { host: api.example.com, paths: [\"/a/**\", \"/b/**\"] }\n  limits: { memory: 2g, cpus: 1, timeout: 1h }\n");
        let split = |rules: &str| zone(&format!("{reach}  forbid:\n{rules}"));
        let both = split("    - { host: api.example.com, paths: [\"/a/**\"] }\n    - { host: api.example.com, paths: [\"/b/**\"] }\n");
        assert_eq!(check(&ask(&both), &bounds(&two)), Ok(()));
        let one = split("    - { host: api.example.com, paths: [\"/a/**\"] }\n");
        assert!(check(&ask(&one), &bounds(&two)).unwrap_err()[0].contains("forbid rule 0"));
        let wider = zone(&format!("{reach}  forbid:\n    - {{ host: \"*.example.com\" }}\n    - {{ host: api.example.com }}\n"));
        assert_eq!(check(&ask(&wider), &bounds(&p)), Ok(()));
    }

    #[test]
    fn segment_globs() {
        let covered = |p: &str, c: &str| path_covered(&[p.to_string()], c);
        // #73: one session's worker channel is within any session's.
        assert!(covered("/v1/code/sessions/*/worker/**", "/v1/code/sessions/abc123/worker/**"));
        assert!(covered("/v1/code/sessions/*/worker", "/v1/code/sessions/abc123/worker"));
        assert!(covered("/a/*/c", "/a/b*/c"));
        assert!(covered("/a/**/z", "/a/b/**/z"));
        assert!(covered("/a/**/z", "/a/z"));
        assert!(covered("/a/{b,c}/*", "/a/c/d"));
        // Not within.
        assert!(!covered("/v1/code/sessions/*/worker/**", "/v1/code/sessions/**"));
        assert!(!covered("/a/*/c", "/a/**/c"));
        assert!(!covered("/a/**", "/a"));
        assert!(!covered("/a/*", "/a/*/b"));
        assert!(!covered("/a/b*", "/a/*"));
        assert!(!covered("/a/**/z", "/a/**"));
        // A brace or class that contains `/` is never split at it, so stays unproven.
        assert!(!covered("/a/*/*", "/a/{b/c,d}"));
        // #111: a class can match `/` even with literal_separator, so `*` doesn't cover it.
        assert!(!covered("/x/*", "/x/*[!~]*[!~]*"));
        assert!(!covered("/x/*", "/x/a[!z]b"));
        assert!(!covered("/x/*", "/x/a[.-0]b"));
        assert!(!covered("/x/*", "/x/{a,b}"));
        assert!(!covered("/x/*", "/x/a\\*"));
        // The same class under a parent that has it is still proven.
        assert!(covered("/x/a[!z]b", "/x/a[!z]b"));
        assert!(covered("/**/a[!z]b", "/x/a[!z]b"));
    }

    /// The structural check must never claim containment the matcher disagrees with: for small globs
    /// and paths, every path a "covered" child matches must match the parent.
    #[test]
    fn segment_proofs_agree_with_the_matcher() {
        // Classes and ranges that match `/` (#111): `[!z]`, `[!~]` and `[.-0]` all do.
        let segs = ["a", "*", "a*", "**", "{a,b}", "", "a[!z]b", "*[!~]*", "[.-0]"];
        let mut globs = vec![];
        for n in 1..=3 {
            let mut idx = vec![0; n];
            loop {
                globs.push(format!("/{}", idx.iter().map(|&i| segs[i]).collect::<Vec<_>>().join("/")));
                let mut k = 0;
                while k < n && idx[k] + 1 == segs.len() {
                    idx[k] = 0;
                    k += 1;
                }
                if k == n {
                    break;
                }
                idx[k] += 1;
            }
        }
        let parts = ["a", "b", "ab", "c", "", "0"];
        let mut paths = vec![];
        for n in 1..=4 {
            for mut x in 0..parts.len().pow(n) {
                let mut p = String::new();
                for _ in 0..n {
                    p.push('/');
                    p.push_str(parts[x % parts.len()]);
                    x /= parts.len();
                }
                paths.push(p);
            }
        }
        let matches: Vec<Vec<bool>> = globs
            .iter()
            .map(|g| {
                let m = crate::manifest::compile_glob(g).unwrap();
                paths.iter().map(|p| m.is_match(p)).collect()
            })
            .collect();
        let (mut proved, mut wrong) = (0, vec![]);
        for (pi, p) in globs.iter().enumerate() {
            for (ci, c) in globs.iter().enumerate() {
                if !path_covered(std::slice::from_ref(p), c) {
                    continue;
                }
                proved += 1;
                if let Some(k) = (0..paths.len()).find(|&k| matches[ci][k] && !matches[pi][k]) {
                    wrong.push(format!("{c} ⊆ {p}, but {} matches only the child", paths[k]));
                }
            }
        }
        assert!(wrong.is_empty(), "{} unsound proofs, e.g.:\n{}", wrong.len(), wrong[..wrong.len().min(10)].join("\n"));
        assert!(proved > 2_000, "only {proved} proofs: the check got too weak");
    }

    /// #153: a child's authority (default its timeout) is never longer than its parent's; an
    /// authority longer than the timeout is the timeout; zero is refused.
    #[test]
    fn authority_narrows() {
        let p = parent();
        let child =
            |l: &str| zone(&format!("  llm: {{ max_requests: 10, max_output_tokens: 1000 }}\n  limits: {{ memory: 1g, cpus: 1, {l} }}\n"));
        assert_eq!(check(&ask(&child("timeout: 10m")), &bounds(&p)), Ok(()));
        assert_eq!(check(&ask(&child("timeout: 10m, authority: 5m")), &bounds(&p)), Ok(()));
        assert_eq!(child("timeout: 10m, authority: 2h").limits.authority().unwrap(), std::time::Duration::from_secs(600));
        let short = zone("  limits: { memory: 2g, cpus: 2, timeout: 1h, authority: 1m }\n");
        let v = check(&ask(&child("timeout: 10m")), &bounds(&short)).unwrap_err();
        assert!(v.iter().any(|v| v.contains("authority 10m: longer than this zone's 1m")), "{v:?}");
    }

    /// #28: input budgets count cached tokens too; a capped zone can only start capped children,
    /// within what it has left.
    #[test]
    fn input_token_caps_narrow() {
        let p = parent();
        let capped = |n: u64| {
            zone(&format!("  llm: {{ max_requests: 10, max_output_tokens: 1000, max_input_tokens: {n} }}\n  limits: {{ memory: 1g, cpus: 1, timeout: 10m }}\n"))
        };
        let uncapped = zone("  llm: { max_requests: 10, max_output_tokens: 1000 }\n  limits: { memory: 1g, cpus: 1, timeout: 10m }\n");
        let left = |n| Bounds { llm_input_remaining: Some(n), ..bounds(&p) };
        assert_eq!(check(&ask(&capped(50_000)), &left(100_000)), Ok(()));
        assert!(check(&ask(&capped(200_000)), &left(100_000)).unwrap_err()[0].contains("only 100000 are left"));
        assert!(check(&ask(&uncapped), &left(100_000)).unwrap_err()[0].contains("no input token cap"));
        // An uncapped parent doesn't constrain its children's input.
        assert_eq!(check(&ask(&uncapped), &bounds(&p)), Ok(()));
        assert_eq!(check(&ask(&capped(10)), &bounds(&p)), Ok(()));
    }

    /// #126: a zero limit is no limit to Docker, so never within a finite parent.
    #[test]
    fn zero_limits_are_never_within() {
        let p = parent();
        let limits = |l: &str| {
            let mut z =
                zone("  llm: { max_requests: 10, max_output_tokens: 1000 }\n  limits: { memory: 1g, cpus: 1, timeout: 10m, pids: 64 }\n");
            match l {
                "memory" => z.limits.memory = "0".into(),
                "memory-half" => z.limits.memory = "0.4b".into(),
                "cpus" => z.limits.cpus = 0.0,
                "cpus-nan" => z.limits.cpus = f32::NAN,
                "cpus-neg" => z.limits.cpus = -1.0,
                "pids" => z.limits.pids = 0,
                "timeout" => z.limits.timeout = "0s".into(),
                _ => {}
            }
            z
        };
        assert_eq!(check(&ask(&limits("")), &bounds(&p)), Ok(()));
        for (l, needle) in [
            ("memory", "memory 0"),
            ("memory-half", "memory 0.4b"),
            ("cpus", "cpus 0"),
            ("cpus-nan", "cpus NaN"),
            ("cpus-neg", "cpus -1"),
            ("pids", "pids 0"),
            ("timeout", "timeout 0s"),
        ] {
            let errs = check(&ask(&limits(l)), &bounds(&p)).unwrap_err().join("\n");
            assert!(errs.contains(needle), "{l}: {errs}");
        }
    }

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_bytes("1500m"), Some(1500 << 20));
        assert_eq!(parse_bytes("2G"), Some(2 << 30));
        assert_eq!(parse_bytes("lots"), None);
    }
}
