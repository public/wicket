//! A zone's policy in Cedar (#51): generated from its manifest, readable (`wicket policy zone`), and
//! what the zone layer of every token minted for it is compiled from.
//!
//! - each reach rule's path becomes a `permit` on its methods: host, glob, and `context.risk <= 2`
//!   unless the rule has `allow_dangerous`;
//! - each forbid path a `forbid` on every method, its glob matched ignoring case;
//! - the spawn ceiling one `permit` on `spawn` (images, isolation floor, limits);
//! - `accept_from` one `permit` on `message`, each injection one on `inject`.
//!
//! [`ceiling_fields`] takes the compiled layer back to the token's zone fields, refusing anything a
//! zone layer can't hold (a zone's Cedar must say what a manifest can).

use crate::compile::{CompileError, Layer};
use crate::schema::METHODS;
use wicket_authz::{Ceiling, Forbid, HostPat, HttpMatch, Inject, PathPat, Reach, SpawnLimits, SpawnMatch, MAX_REACH_RISK};
use wicket_core::ZoneSpec;

/// A Cedar string literal.
pub fn lit(s: &str) -> String {
    let mut out = String::from("\"");
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() || !c.is_ascii() => out.push_str(&format!("\\u{{{:x}}}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn actions(methods: &[String]) -> String {
    let list: Vec<String> = methods.iter().map(|m| format!("Action::{}", lit(&m.to_ascii_uppercase()))).collect();
    format!("[{}]", list.join(", "))
}

fn host_cond(h: &str) -> String {
    let h = h.to_ascii_lowercase();
    match h.strip_prefix('*') {
        Some(rest) => format!("resource.host like {}", lit(&format!("*{}", rest.replace('*', "\\*")))),
        None => format!("resource.host == {}", lit(&h)),
    }
}

/// The zone's policy as Cedar text, from the ceiling a manifest gives (`Ceiling::from_zone`).
pub fn cedar(zone: &ZoneSpec, base: &Ceiling) -> String {
    let mut out = format!("// zone {}: generated from its manifest (#51). Every token minted in it is compiled from this.\n", zone.name);
    for (i, r) in base.reach.iter().enumerate() {
        for g in &r.paths {
            let risk = if r.allow_dangerous { String::new() } else { format!(" && context.risk <= {MAX_REACH_RISK}") };
            out.push_str(&format!(
                "@id({})\npermit(principal, action in {}, resource) when {{ {} && resource.path_matches.contains({}){risk} }};\n",
                lit(&format!("reach {i} {g}")),
                actions(&r.methods),
                host_cond(&r.host),
                lit(g)
            ));
        }
    }
    let all: Vec<String> = METHODS.iter().map(|m| m.to_string()).collect();
    for (i, f) in base.forbid.iter().enumerate() {
        for g in &f.paths {
            out.push_str(&format!(
                "@id({})\nforbid(principal, action in {}, resource) when {{ {} && resource.path_matches_any_case.contains({}) }};\n",
                lit(&format!("forbid {i} {g}")),
                actions(&all),
                host_cond(&f.host),
                lit(g)
            ));
        }
    }
    let s = &base.spawn;
    let images: Vec<String> = s.images.iter().map(|i| format!("Image::{}", lit(i))).collect();
    // (No images: no spawn permit. Cedar refuses an empty set, and nothing could be started.)
    if !images.is_empty() {
        out.push_str(&format!(
            "@id(\"spawn\")\npermit(principal, action == Action::\"spawn\", resource) when {{ resource in [{}] && context.isolation >= {} && context.memory <= {} && context.cpus_milli <= {} && context.pids <= {} && context.timeout_s <= {} }};\n",
            images.join(", "),
            s.min_isolation,
            s.mem_bytes,
            s.cpus_milli,
            s.pids,
            s.timeout_s
        ));
    }
    let from: Vec<String> = base.accept_from.iter().map(|z| format!("Zone::{}", lit(z))).collect();
    if !from.is_empty() {
        out.push_str(&format!(
            "@id(\"messages\")\npermit(principal, action == Action::\"message\", resource) when {{ resource in [{}] }};\n",
            from.join(", ")
        ));
    }
    for (i, j) in base.inject.iter().enumerate() {
        out.push_str(&format!(
            "@id({})\npermit(principal, action == Action::\"inject\", resource == Secret::{}) when {{ context.host == {} && context.header == {} }};\n",
            lit(&format!("inject {i}")),
            lit(&j.secret),
            lit(&j.host),
            lit(&j.header)
        ));
    }
    out
}

fn bad<T>(msg: impl Into<String>) -> Result<T, CompileError> {
    Err(CompileError::Unsupported { id: "zone".into(), msg: msg.into() })
}

fn one_host(m: &HttpMatch) -> Result<String, CompileError> {
    match (m.hosts.as_slice(), m.not_hosts.is_empty()) {
        ([HostPat::Exact(h)], true) => Ok(h.clone()),
        ([HostPat::Suffix(s)], true) => Ok(format!("*{s}")),
        _ => bad("a zone rule names exactly one host"),
    }
}

/// The token's zone fields from a compiled zone layer, over `base` (whose other fields, the
/// structural ones and the model budget, aren't policy).
pub fn ceiling_fields(layer: &Layer, base: &Ceiling) -> Result<Ceiling, CompileError> {
    let all: Vec<String> = METHODS.iter().map(|m| m.to_string()).collect();
    let Some(http) = &layer.http else { return bad("a zone permits HTTP only by its reach rules, not unconditionally") };
    let mut reach = vec![];
    for m in http {
        let path = match m.paths.as_slice() {
            [PathPat::Glob(g)] => g.clone(),
            _ => return bad("a reach rule has exactly one path glob (resource.path_matches.contains)"),
        };
        if m.min_risk.is_some() || m.max_risk.is_some_and(|r| r != MAX_REACH_RISK) {
            return bad(format!("a reach rule bounds risk only as context.risk <= {MAX_REACH_RISK}, or not at all"));
        }
        reach.push(Reach {
            host: one_host(m)?,
            methods: m.methods.clone().unwrap_or_else(|| all.clone()),
            paths: vec![path],
            allow_dangerous: m.max_risk.is_none(),
        });
    }
    let mut forbid = vec![];
    for m in &layer.forbid {
        let path = match m.paths.as_slice() {
            [PathPat::GlobAnyCase(g)] => g.clone(),
            _ => return bad("a zone forbid has exactly one path glob, ignoring case (resource.path_matches_any_case.contains)"),
        };
        if m.min_risk.is_some() || m.max_risk.is_some() || m.methods.as_ref().is_some_and(|ms| ms.len() != all.len()) {
            return bad("a zone forbid applies to every method and risk");
        }
        forbid.push(Forbid { host: one_host(m)?, paths: vec![path] });
    }
    let spawn = match layer.spawn.as_deref() {
        Some(
            [SpawnMatch {
                images: Some(images),
                min_isolation: Some(iso),
                max_mem_bytes: Some(mem),
                max_cpus_milli: Some(cpu),
                max_pids: Some(pids),
                max_timeout_s: Some(secs),
            }],
        ) => SpawnLimits { images: images.clone(), min_isolation: *iso, mem_bytes: *mem, cpus_milli: *cpu, pids: *pids, timeout_s: *secs },
        // No image to start: nothing spawns, whatever the limits (kept as the manifest says).
        Some([]) if base.spawn.images.is_empty() => base.spawn.clone(),
        _ => return bad("a zone has one spawn permit, naming its images, isolation floor and every limit"),
    };
    let Some(accept_from) = layer.msg_from.clone() else { return bad("a zone names the zones it accepts messages from") };
    let Some(keys) = &layer.inject else { return bad("a zone names its injections") };
    let mut inject = vec![];
    for k in keys {
        let mut parts = k.splitn(3, '|');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(hd), Some(s)) => inject.push(Inject { host: h.into(), header: hd.into(), secret: s.into() }),
            _ => return bad(format!("injection {k:?}")),
        }
    }
    Ok(Ceiling { reach, forbid, spawn, accept_from, inject, ..base.clone() })
}
