//! A concrete evaluator for the modelled request space: `op::evaluate` with the risk class
//! replaced by a free `dangerous` flag, globs matched by wicket's own globset code. Used to replay
//! SymCC counterexamples and to difference-test the compiler.

use wicket_core::canonical_path;
use wicket_core::manifest::{host_matches, ForbidRule, ZoneSpec};

#[derive(Debug, Clone, PartialEq)]
pub enum V {
    /// Not a request the proxy would evaluate (non-canonical path or host, or a host no sandbox reaches).
    Invalid,
    Forbidden(usize),
    Allow(usize),
    /// Matched reach rule i, but is dangerous and the rule lacks allow_dangerous.
    NeedsGrantDangerous(usize),
    OutsideReach,
}

pub fn glob_match(glob: &str, path: &str) -> bool {
    ForbidRule { host: "x".into(), paths: vec![glob.into()] }.matches("x", path)
}

pub fn host_ok(h: &str) -> bool {
    !(h.is_empty()
        || h.starts_with('.')
        || h.ends_with('.')
        || h.contains("..")
        || h.contains(['/', ':', '*', ' '])
        || h == "localhost"
        || h.ends_with(".localhost")
        || ["metadata", "metadata.google.internal", "169.254.169.254", "100.100.100.200"].contains(&h))
}

pub fn eval(z: &ZoneSpec, method: &str, host: &str, path: &str, dangerous: bool) -> V {
    if !host_ok(host) || canonical_path(path).ok() != Some(path) || path.contains('?') || path.starts_with("//") {
        return V::Invalid;
    }
    if let Some(k) = z.forbid.iter().position(|f| f.matches(host, path)) {
        return V::Forbidden(k);
    }
    for (i, r) in z.reach.iter().enumerate() {
        if !host_matches(&r.host, host) || !r.methods.iter().any(|m| m.eq_ignore_ascii_case(method)) {
            continue;
        }
        if !r.paths.iter().any(|g| glob_match(g, path)) {
            continue;
        }
        if dangerous && !r.allow_dangerous {
            return V::NeedsGrantDangerous(i);
        }
        return V::Allow(i);
    }
    V::OutsideReach
}

pub fn describe(z: &ZoneSpec, v: &V) -> String {
    match v {
        V::Invalid => "not a canonical request".into(),
        V::Forbidden(k) => format!("forbidden by forbid rule {k} ({} {:?})", z.forbid[*k].host, z.forbid[*k].paths),
        V::Allow(i) => {
            let r = &z.reach[*i];
            format!("allowed by reach rule {i} ({} {:?} {:?}{})", r.host, r.methods, r.paths, if r.allow_dangerous { " allow_dangerous" } else { "" })
        }
        V::NeedsGrantDangerous(i) => format!("needs a grant: matches reach rule {i} but is dangerous and that rule lacks allow_dangerous"),
        V::OutsideReach => "needs a grant: outside reach".into(),
    }
}
