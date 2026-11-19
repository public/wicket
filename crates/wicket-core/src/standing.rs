//! Standing reach (#572), the pure part: narrowing an ask to its evidence. The ledger keeps the
//! asks and their evidence (wicket-store), the control host decides them (wicket-control); what a
//! narrowed rule is depends only on the evidence's ops, so it is here, where the Lean spec's oracle
//! (verification/lean, `Wicket/Standing.lean`) checks it.

use crate::manifest::ReachRule;
use crate::op::STANDING_PAIRS;

/// `host`'s rule narrowed to what the evidence shows a human let through: of `ops` (each blocked
/// request's method, path and how often it was granted), the method and path pairs that were
/// granted, exactly, and nothing else (#572 review, M2). One rule is every method × every path, so
/// where the granted methods were on different paths only the most granted method (and any others
/// granted on exactly its paths) is kept: never a pair the evidence lacks. No `allow_dangerous`
/// (the evidence says nothing of risk: the operator adds it by editing). At most
/// [`STANDING_PAIRS`] pairs, the most granted paths first. None if nothing was granted.
///
/// Lean: `narrow`; `narrow_pairs_granted`, `narrow_not_dangerous` and `narrow_allows_only_evidence`.
pub fn narrow<'a>(host: &str, ops: impl IntoIterator<Item = (&'a str, &'a str, u64)>) -> Option<ReachRule> {
    use std::collections::BTreeMap;
    let mut by: BTreeMap<&str, (u64, Vec<String>)> = BTreeMap::new();
    for (method, path, granted) in ops.into_iter().filter(|o| o.2 > 0) {
        let e = by.entry(method).or_default();
        e.0 += granted;
        let p = glob_literal(path);
        if !e.1.contains(&p) {
            e.1.push(p);
        }
    }
    let (top, (_, paths)) = by.iter().max_by_key(|(m, (n, _))| (*n, std::cmp::Reverse(**m)))?;
    let mut sorted = paths.clone();
    sorted.sort();
    let methods: Vec<String> = by
        .iter()
        .filter(|(m, (_, p))| {
            m == &top || {
                let mut q = p.clone();
                q.sort();
                q == sorted
            }
        })
        .map(|(m, _)| m.to_string())
        .collect();
    let keep = (STANDING_PAIRS / methods.len()).max(1);
    let paths: Vec<String> = paths.iter().take(keep).cloned().collect();
    Some(ReachRule { host: host.to_string(), methods, paths, allow_dangerous: false }.canonical())
}

/// `path` as a glob that matches only itself: each glob metacharacter in a class of its own.
///
/// Lean: `globLit`; `globLit_plain` (a path without them is its own glob).
pub fn glob_literal(path: &str) -> String {
    path.chars().map(|c| if "*?[]{}\\".contains(c) { format!("[{c}]") } else { c.to_string() }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Op, RunId, TenantId};

    /// A path with glob metacharacters, as its literal glob, matches itself and nothing else that
    /// differs only where they are (the Lean spec leaves classes out of its language, so this is
    /// tested here, not proved).
    #[test]
    fn a_literal_glob_matches_only_its_path() {
        let rule = |p: &str| ReachRule { host: "a.test".into(), methods: vec!["GET".into()], paths: vec![p.into()], allow_dangerous: true };
        let op = |p: &str| Op::egress(&TenantId::single(), &RunId(String::new()), "z", "GET", "a.test", p);
        let paths = ["/a*b", "/a?b", "/[x]", "/a]b", "/a{b,c}", "/**", "/a/*", "/a\\b", "/*/x"];
        let others = ["/aXb", "/ab", "/x", "/a/b", "/a", "/ac", "/abc", "/a{b", "/a/", "/y/x", "/ab]"];
        for p in paths {
            let g = glob_literal(p);
            assert!(rule(&g).allows(&op(p)).unwrap(), "{g} matches {p}");
            for q in paths.iter().chain(&others).filter(|q| **q != p) {
                assert!(!rule(&g).allows(&op(q)).unwrap(), "{g} (for {p}) matches {q}");
            }
        }
    }
}
