//! Target 4: manifests, as wicket reads them: YAML through `wicket_agent::load`, then the zone
//! compiled (`CompiledZone::new`), its ceiling made (`Ceiling::from_zone`) and compiled from Cedar
//! (`wicket_policy::ceiling`, what a token is minted from), and subset admission between two zones.
//!
//! The input is one manifest, or two separated by a line `---8<---` (a parent, then a child that
//! parent's agent asks to start). The oracle: nothing panics (a manifest that parses compiles or is
//! refused); and when `subset::check` admits the child, every probe the child's zone allows by reach
//! the parent's allows by reach too (authority only narrows).

use std::time::Duration;
use wicket_core::subset::{self, Ask, Bounds};
use wicket_core::{CompiledZone, Op, RunId, TenantId, Verdict, ZoneSpec};

pub const SEPARATOR: &str = "\n---8<---\n";

pub fn run(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else { return };
    let (a, b) = match text.split_once(SEPARATOR) {
        Some((a, b)) => (a, Some(b)),
        None => (text, None),
    };
    let Some(parent) = one(a) else { return };
    let Some(b) = b else { return };
    let Some(child) = one(b) else { return };
    let (pz, cz) = (&parent.zone, &child.zone);
    let _ = subset::unapprovable(&child.zone, &parent.zone);
    let _ = subset::reach_within(&parent.zone, &child.zone);
    let bounds = Bounds {
        zone: &parent.zone,
        images: vec!["img:a".into()],
        llm_remaining: Some((1000, 1_000_000)),
        llm_input_remaining: None,
        time_remaining: Duration::from_secs(86_400),
        child_slots: 10,
    };
    let ask = Ask { zone: &child.zone, image: "img:a", max_children: 0 };
    if subset::check(&ask, &bounds).is_ok() {
        let (Ok(p), Ok(c)) = (CompiledZone::new(pz.clone()), CompiledZone::new(cz.clone())) else { return };
        for o in probes(cz) {
            if matches!(c.evaluate(&o), Verdict::AllowByReach(_)) {
                assert!(
                    matches!(p.evaluate(&o), Verdict::AllowByReach(_)),
                    "admitted as a subset, but the child allows {} {}{} by reach and the parent doesn't ({:?})",
                    o.method,
                    o.host,
                    o.path,
                    p.evaluate(&o)
                );
            }
        }
    }
}

/// One manifest through everything a zone goes through; the manifest if it loaded.
fn one(yaml: &str) -> Option<wicket_core::Manifest> {
    let m = wicket_agent::load(yaml).ok()?;
    let z = m.zone.clone();
    let compiled = CompiledZone::new(z.clone());
    let _ = wicket_policy::zone::lit(&z.name);
    if let Ok(cz) = &compiled {
        for o in probes(&z) {
            let _ = cz.evaluate(&o);
        }
        let _ = cz.host_verdict("api.github.com");
        if let Ok(base) = wicket_authz::Ceiling::from_zone(&z, "run_a", 1_800_000_000, vec![]) {
            let _ = wicket_policy::zone::cedar(&z, &base);
            let _ = wicket_policy::ceiling(&z, "run_a", 1_800_000_000, vec![], &[], None);
        }
    }
    Some(m)
}

/// Requests a zone's rules are about: each reach and forbid rule's host (wildcards made concrete)
/// with each of its methods and its path globs made concrete, plus a few fixed ones.
fn probes(z: &ZoneSpec) -> Vec<Op> {
    let t = TenantId::single();
    let run = RunId("run_a".into());
    let mut v = Vec::new();
    let concrete = |p: &str| p.replace("**", "a/b").replace('*', "x").replace('?', "q");
    for r in z.reach.iter().take(16) {
        let host = r.host.replace('*', "w");
        for m in r.methods.iter().take(8) {
            for p in r.paths.iter().take(8) {
                let path = concrete(p);
                v.push(Op::egress(&t, &run, &z.name, m, &host, &path));
                v.push(Op::egress(&t, &run, &z.name, m, &host, &format!("{path}/git-receive-pack")));
            }
        }
    }
    for (m, h, p) in [("GET", "api.github.com", "/"), ("POST", "api.github.com", "/repos/a/b/hooks")] {
        v.push(Op::egress(&t, &run, &z.name, m, h, p));
    }
    v
}
