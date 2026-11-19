//! Which hosts the egress proxy inspects and which it splices through (#62).
//!
//! The egress proxy terminates TLS for a host so it can decide each request: its method, path and
//! risk, and attach a credential. A host that a zone allows *wholesale* (every method, every path,
//! nothing attached, nothing forbidden) gains nothing from that: every request the decision
//! function could see would be allowed by reach, without a grant or a credential. For those hosts
//! the proxy decides on the hostname when the box connects and relays the encrypted bytes
//! unmodified ("spliced"), with no TLS work.
//!
//! [`inspection`] is the one place that decides this. It is conservative: anything it doesn't
//! recognise as wholesale is inspected. The proxy adds the checks that depend on the run rather than
//! the zone (credential swaps, the model gate, a node's decisions), and the ClientHello's SNI must
//! name the CONNECT host.
//!
//! What a spliced host gives up, by construction: per-request audit rows (one row per connection,
//! with byte counts, instead), the request header allow-list, dropping the box's own
//! `Authorization`, the request-shape checks, and Host pinning. The last means a spliced host on a
//! shared CDN can be used to reach other sites behind the same CDN (domain fronting), which is why
//! the zone view says which hosts are spliced.

use crate::manifest::{host_matches, label_under, ZoneSpec};
use crate::op::{never_reachable, HTTP_METHODS};

/// Hosts (and host patterns) for which the dangerous-pattern list (`op::classify`) can rate a
/// request R3 or higher. For these, a reach rule allows every request only with `allow_dangerous`.
/// The property test in this module checks that `classify` raises risk for no other host.
pub const RISK_HOSTS: &[&str] = &["github.com", "api.github.com", "*.amazonaws.com", "metadata.google.internal", "169.254.169.254"];

/// How the egress proxy treats connections to a host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inspection {
    /// Decided on the hostname at CONNECT, then relayed without terminating TLS. `rule` is the reach
    /// rule that allows the host wholesale.
    Spliced { rule: usize },
    /// TLS is terminated and every request is decided on its own; the reason says why.
    Inspected(String),
}

impl Inspection {
    pub fn is_spliced(&self) -> bool {
        matches!(self, Inspection::Spliced { .. })
    }
}

/// Whether some host matches both patterns (`*.example.com`, or an exact name). For an exact
/// `b`, this is [`host_matches`]`(a, b)` when `a` has no trailing dot; with one it is wider (the
/// overlap trims a pattern's trailing dots, matching doesn't), which only inspects more.
pub fn patterns_overlap(a: &str, b: &str) -> bool {
    // Over bytes, ignoring ASCII case and trailing dots, without allocating (Kani checks it, #325).
    fn trim(mut x: &[u8]) -> &[u8] {
        while let [rest @ .., b'.'] = x {
            x = rest;
        }
        x
    }
    let (a, b) = (trim(a.as_bytes()), trim(b.as_bytes()));
    match (a.strip_prefix(b"*."), b.strip_prefix(b"*.")) {
        (None, None) => a.eq_ignore_ascii_case(b),
        (Some(s), None) => b.len() > s.len() + 1 && label_under(b, s),
        (None, Some(t)) => a.len() > t.len() + 1 && label_under(a, t),
        // Two wildcards share names when one suffix is the other or lies under it.
        (Some(s), Some(t)) => s.eq_ignore_ascii_case(t) || label_under(s, t) || label_under(t, s),
    }
}

/// Whether a reach rule allows every request to its host by itself: the path `/**`, every method
/// the proxy forwards, and (where the dangerous-pattern list could rate a request R3 or higher)
/// `allow_dangerous`.
fn wholesale(rule: &crate::ReachRule, host: &str) -> bool {
    let every_path = rule.paths.iter().any(|p| p == "/**");
    let every_method = HTTP_METHODS.iter().all(|m| rule.methods.iter().any(|x| x.eq_ignore_ascii_case(m)));
    let risky = RISK_HOSTS.iter().any(|r| patterns_overlap(r, host));
    every_path && every_method && (rule.allow_dangerous || !risky)
}

/// The model hosts of a zone: its model route's upstream (filled in from the harness's default when
/// the manifest is loaded). Its calls go through the model proxy's budget and checks, so it is
/// always inspected. (The egress proxy also never splices its provider profile's own host while a
/// model route is set: `wicket-proxy`'s `splice_rule`.)
fn model_hosts(zone: &ZoneSpec) -> Vec<String> {
    zone.llm
        .as_ref()
        .and_then(|l| url::Url::parse(&l.upstream).ok())
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .into_iter()
        .collect()
}

/// How the egress proxy treats `host` (an exact name, or a reach rule's `*.` pattern for the zone
/// view, where the answer holds for every name the pattern matches).
pub fn inspection(zone: &ZoneSpec, host: &str) -> Inspection {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let concrete = !host.starts_with("*.");
    if concrete && never_reachable(&host).is_some() {
        return Inspection::Inspected("never reachable".into());
    }
    if let Some(f) = zone.forbid.iter().find(|f| patterns_overlap(&f.host, &host)) {
        return Inspection::Inspected(format!("a forbid rule names {}", f.host));
    }
    if let Some(i) = zone.inject.iter().find(|i| patterns_overlap(&i.host, &host)) {
        return Inspection::Inspected(format!("a credential is injected for {}", i.host));
    }
    if let Some(m) = model_hosts(zone).into_iter().find(|m| patterns_overlap(m, &host)) {
        return Inspection::Inspected(format!("model host {m}"));
    }
    // For a pattern, the rule must cover every name the pattern matches: its own host is the same
    // pattern or a wider one.
    let covers = |rule: &crate::ReachRule| if concrete { rule.host_matches(&host) } else { covers_pattern(&rule.host, &host) };
    match zone.reach.iter().position(|r| covers(r) && wholesale(r, &host)) {
        Some(rule) => Inspection::Spliced { rule },
        None if zone.reach.iter().any(covers) => Inspection::Inspected("reach limits methods, paths or risk".into()),
        None => Inspection::Inspected("not in reach".into()),
    }
}

/// Whether every name `pattern` matches is matched by `rule_host` too.
fn covers_pattern(rule_host: &str, pattern: &str) -> bool {
    let r = rule_host.to_ascii_lowercase();
    match (r.strip_prefix("*."), pattern.strip_prefix("*.")) {
        (_, None) => host_matches(&r, pattern),
        (None, Some(_)) => false,
        (Some(s), Some(t)) => s == t || t.ends_with(&format!(".{s}")),
    }
}

/// One line per host the zone's reach names: spliced or inspected, and why (the zone view).
pub fn view(zone: &ZoneSpec) -> Vec<(String, Inspection)> {
    let mut seen = Vec::new();
    for r in &zone.reach {
        let h = r.host.trim_end_matches('.').to_ascii_lowercase();
        if !seen.iter().any(|(s, _): &(String, Inspection)| *s == h) {
            let i = inspection(zone, &h);
            seen.push((h, i));
        }
    }
    seen
}

/// Whether a host is inside one X.509 permitted DNS subtree, as a verifier reads it (a node CA's
/// name constraints, #257): `api.example.com` permits itself and every name under it;
/// `.example.org` permits names under it, not the apex; `*` (the control host's own node) any name.
pub fn subtree_permits(subtree: &str, host: &str) -> bool {
    if subtree == "*" {
        return true;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let subtree = subtree.to_ascii_lowercase();
    match subtree.strip_prefix('.') {
        Some(base) => host.len() > base.len() + 1 && host.ends_with(&subtree),
        None => host == subtree || host.ends_with(&format!(".{subtree}")),
    }
}

/// Whether permitted subtree `p` covers every name needed subtree `need` stands for (both in name
/// constraint form: `h` for `h` and every name under it, `.d` for the names under `d`).
fn subtree_covers(p: &str, need: &str) -> bool {
    if p == "*" {
        return true;
    }
    let p = p.to_ascii_lowercase();
    let need = need.to_ascii_lowercase();
    match need.strip_prefix('.') {
        // Every name under d: p is d itself (either form) or an ancestor of d.
        Some(d) => p == d || p.strip_prefix('.') == Some(d) || subtree_permits(&p, d),
        // h and every name under it: p is h, or an ancestor of h.
        None => p == need || subtree_permits(&p, &need),
    }
}

/// The name constraints a box's node CA needs for it (#573): every inspected host its zone reaches,
/// injects into or calls as its model host, and `extra` (the hosts of its credential swaps and of
/// the grants published for it), as subtrees (`h`, or `.d` for `*.d`). Spliced hosts need no
/// certificate, and hosts wicket never reaches are left out. Entries another entry covers are
/// dropped, and the list is sorted.
pub fn ca_hosts(zone: &ZoneSpec, extra: &[String]) -> Vec<String> {
    let mut want: Vec<String> = vec![];
    let candidates = zone
        .reach
        .iter()
        .map(|r| r.host.clone())
        .chain(zone.inject.iter().map(|i| i.host.clone()))
        .chain(model_hosts(zone))
        .chain(extra.iter().cloned());
    for h in candidates {
        let h = h.trim_end_matches('.').to_ascii_lowercase();
        let concrete = h.strip_prefix("*.").unwrap_or(&h).to_string();
        if concrete.is_empty() || never_reachable(&concrete).is_some() || inspection(zone, &h).is_spliced() {
            continue;
        }
        let entry = match h.strip_prefix("*.") {
            Some(d) => format!(".{d}"),
            None => h,
        };
        if !want.contains(&entry) {
            want.push(entry);
        }
    }
    let mut kept: Vec<String> = want.iter().filter(|e| !want.iter().any(|o| o != *e && subtree_covers(o, e))).cloned().collect();
    kept.sort();
    kept
}

/// The entries of `needed` (as [`ca_hosts`] gives them) that a CA permitting `permitted` doesn't
/// cover: what a renewal would have to add.
pub fn uncovered(permitted: &[String], needed: &[String]) -> Vec<String> {
    needed.iter().filter(|n| !permitted.iter().any(|p| subtree_covers(p, n))).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::{CompiledZone, Op, Verdict};
    use crate::{Manifest, RiskClass, RunId, TenantId};

    /// #325: what Kani's `patterns_that_share_a_host_overlap` states, exhaustively over every pattern
    /// of up to four bytes of `ab.*` and every host of up to four of `ab.` (Kani goes to five).
    #[test]
    fn patterns_that_share_a_host_overlap_exhaustively() {
        fn all(alphabet: &[u8], n: usize) -> Vec<String> {
            let mut out = vec![String::new()];
            let mut last = vec![String::new()];
            for _ in 0..n {
                last = last.iter().flat_map(|s| alphabet.iter().map(move |c| format!("{s}{}", *c as char))).collect();
                out.extend(last.iter().cloned());
            }
            out
        }
        let (pats, hosts) = (all(b"ab.*", 4), all(b"ab.", 4));
        for a in &pats {
            for h in &hosts {
                let (m, o) = (host_matches(a, h), patterns_overlap(a, h));
                if a.ends_with('.') {
                    assert!(o || !m, "{a:?} {h:?}");
                } else {
                    assert_eq!(o, m, "{a:?} {h:?}");
                }
            }
            for b in &pats {
                let o = patterns_overlap(a, b);
                assert_eq!(o, patterns_overlap(b, a), "{a:?} {b:?}");
                if !o {
                    assert!(!hosts.iter().any(|h| host_matches(a, h) && host_matches(b, h)), "{a:?} {b:?}");
                }
            }
        }
    }

    /// #325: `patterns_overlap` works on bytes now (for Kani); it decides as the lowercasing form did.
    #[test]
    fn patterns_overlap_decides_as_lowercasing_did() {
        let old = |a: &str, b: &str| {
            let a = a.trim_end_matches('.').to_ascii_lowercase();
            let b = b.trim_end_matches('.').to_ascii_lowercase();
            match (a.strip_prefix("*."), b.strip_prefix("*.")) {
                (None, None) => a == b,
                (Some(_), None) => host_matches(&a, &b),
                (None, Some(_)) => host_matches(&b, &a),
                (Some(s), Some(t)) => s == t || s.ends_with(&format!(".{t}")) || t.ends_with(&format!(".{s}")),
            }
        };
        let names = [
            "",
            ".",
            "*.",
            "*.*",
            "*",
            "a",
            "A.",
            "a.b",
            "A.B..",
            "*.a",
            "*.A.",
            "*.b",
            "*.a.b",
            "*.b.a",
            "x.a.b",
            "*.x.a.b",
            "github.com",
            "*.github.com",
            "API.GitHub.com.",
            "é.a",
            "*.é.a",
            "ab",
            "*.ab",
            "b.ab",
        ];
        for a in names {
            for b in names {
                assert_eq!(patterns_overlap(a, b), old(a, b), "{a:?} {b:?}");
            }
        }
    }

    fn zone(body: &str) -> ZoneSpec {
        Manifest::from_yaml(&format!("task: t\nagent: {{name: a}}\nzone:\n  name: z\n  llm: {{}}\n{body}")).unwrap().zone
    }

    const ALL: &str = "[GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE]";

    /// #175: an optional injection whose secret isn't set is dropped from the zone, so a host it was
    /// the only injection for is spliced when reach allows it wholesale; a set or required one stays.
    #[test]
    fn a_host_whose_only_injection_is_unset_and_optional_is_spliced() {
        let body = format!(
            "  reach: [{{host: static.example, methods: {ALL}}}, {{host: other.example, methods: {ALL}}}]\n  inject:\n    - {{host: static.example, header: Authorization, secret: unset, optional: true}}\n    - {{host: other.example, header: Authorization, secret: set, optional: true}}\n    - {{host: other.example, header: X-Key, secret: required}}"
        );
        let mut z = zone(&body);
        assert!(!inspection(&z, "static.example").is_spliced(), "inspected while the rule is there");
        let dropped = z.drop_unset_optional_injections(|s| s == "set");
        assert_eq!(dropped.iter().map(|i| i.secret.as_str()).collect::<Vec<_>>(), ["unset"]);
        assert_eq!(z.inject.iter().map(|i| i.secret.as_str()).collect::<Vec<_>>(), ["set", "required"]);
        assert_eq!(inspection(&z, "static.example"), Inspection::Spliced { rule: 0 });
        assert!(!inspection(&z, "other.example").is_spliced(), "still injected");
    }

    #[test]
    fn which_rules_qualify() {
        let spliced = |body: &str, host: &str| inspection(&zone(body), host).is_spliced();
        let all = format!("  reach: [{{host: static.example, methods: {ALL}}}]");
        assert!(spliced(&all, "static.example"));
        assert!(spliced(&all, "STATIC.example."));
        assert!(!spliced(&all, "other.example"), "not in reach");
        // Default methods (GET, HEAD) aren't every method; a narrower path isn't every path.
        assert!(!spliced("  reach: [{host: static.example}]", "static.example"));
        assert!(!spliced(&format!("  reach: [{{host: static.example, methods: {ALL}, paths: ['/pub/**']}}]"), "static.example"));
        assert!(!spliced(&format!("  reach: [{{host: static.example, methods: {ALL}, paths: ['/*']}}]"), "static.example"));
        // Lower-case methods count.
        assert!(spliced("  reach: [{host: s.example, methods: [get, head, options, post, put, patch, delete]}]", "s.example"));
        // Any forbid rule naming the host, whatever its paths, or an injected credential.
        assert!(!spliced(&format!("{all}\n  forbid: [{{host: static.example, paths: ['/admin/**']}}]"), "static.example"));
        assert!(!spliced(&format!("{all}\n  forbid: [{{host: '*.example', paths: ['/x']}}]"), "static.example"));
        assert!(!spliced(&format!("{all}\n  inject: [{{host: static.example, header: Authorization, secret: s}}]"), "static.example"));
        // A narrower reach rule beside the wholesale one doesn't narrow it (reach is a union).
        let z = zone(&format!("  reach:\n    - {{host: static.example, paths: ['/x']}}\n    - {{host: static.example, methods: {ALL}}}"));
        assert_eq!(inspection(&z, "static.example"), Inspection::Spliced { rule: 1 });
        // Hosts the dangerous-pattern list knows need allow_dangerous.
        for h in ["github.com", "api.github.com", "s3.amazonaws.com"] {
            assert!(!spliced(&format!("  reach: [{{host: '{h}', methods: {ALL}}}]"), h), "{h}");
            assert!(spliced(&format!("  reach: [{{host: '{h}', methods: {ALL}, allow_dangerous: true}}]"), h), "{h}");
        }
        // The model host never.
        let mut z = zone(&format!("  reach: [{{host: models.example, methods: {ALL}}}]"));
        assert!(inspection(&z, "models.example").is_spliced());
        z.llm.as_mut().unwrap().upstream = "https://models.example".into();
        assert!(!inspection(&z, "models.example").is_spliced());
        // Wildcards: names under the pattern, and the view's answer for the pattern itself.
        let w = format!("  reach: [{{host: '*.cdn.example', methods: {ALL}}}]\n  forbid: [{{host: bad.cdn.example}}]");
        assert!(spliced(&w, "a.cdn.example"));
        assert!(!spliced(&w, "bad.cdn.example"));
        assert!(!spliced(&w, "*.cdn.example"), "the pattern overlaps a forbidden name");
        assert!(spliced(&format!("  reach: [{{host: '*.cdn.example', methods: {ALL}}}]"), "*.cdn.example"));
        assert!(!spliced(&format!("  reach: [{{host: 'x.cdn.example', methods: {ALL}}}]"), "*.cdn.example"));
        assert!(!spliced(&format!("  reach: [{{host: '*.amazonaws.com', methods: {ALL}}}]"), "*.amazonaws.com"));
        assert!(!spliced(&format!("  reach: [{{host: '*.com', methods: {ALL}}}]"), "*.com"), "covers github.com");
    }

    #[test]
    fn the_wholesale_path_glob_matches_the_root_too() {
        let z = CompiledZone::new(zone(&format!("  reach: [{{host: s.example, methods: {ALL}}}]"))).unwrap();
        let op = Op::egress(&TenantId::single(), &RunId("r".into()), "z", "GET", "s.example", "/");
        assert_eq!(z.evaluate(&op), Verdict::AllowByReach(0));
    }

    #[test]
    fn overlap() {
        assert!(patterns_overlap("a.example", "A.example."));
        assert!(!patterns_overlap("a.example", "b.example"));
        assert!(patterns_overlap("*.example", "a.example") && patterns_overlap("a.example", "*.example"));
        assert!(!patterns_overlap("*.example", "example"));
        assert!(patterns_overlap("*.a.example", "*.example") && patterns_overlap("*.example", "*.a.example"));
        assert!(!patterns_overlap("*.a.example", "*.b.example"));
    }

    /// A small deterministic generator (no external crate): xorshift.
    struct Rng(u64);
    impl Rng {
        fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            &xs[(self.0 % xs.len() as u64) as usize]
        }
    }

    /// The property: a host that is spliced is one where every request the decision function could
    /// see is allowed by reach, with no credential attached. Requests are drawn from the
    /// dangerous-pattern list's own vocabulary (pushes, GraphQL, hooks, merges, ...), so a path that
    /// raises risk is actually tried.
    #[test]
    fn a_spliced_host_allows_every_request_without_a_credential() {
        let hosts = [
            "static.example",
            "a.cdn.example",
            "bad.cdn.example",
            "github.com",
            "api.github.com",
            "s3.amazonaws.com",
            "api.anthropic.com",
            "registry.npmjs.org",
            "models.example",
        ];
        let segs = [
            "repos",
            "o",
            "r",
            "graphql",
            "hooks",
            "merge",
            "merges",
            "actions",
            "contents",
            ".github",
            "git",
            "refs",
            "info",
            "git-receive-pack",
            "git-upload-pack",
            "pulls",
            "1",
            "update-branch",
            "keys",
            "secrets",
            "comments",
            "admin",
            "issues",
            "collaborators",
            "dispatches",
            "releases",
            "x",
        ];
        let queries = ["", "service=git-receive-pack", "service=git-upload-pack", "service=git-upload-pack&x=1"];
        let rules = [
            format!("{{host: static.example, methods: {ALL}}}"),
            format!("{{host: '*.cdn.example', methods: {ALL}}}"),
            format!("{{host: github.com, methods: {ALL}}}"),
            format!("{{host: github.com, methods: {ALL}, allow_dangerous: true}}"),
            format!("{{host: api.github.com, methods: {ALL}}}"),
            format!("{{host: api.github.com, methods: {ALL}, allow_dangerous: true}}"),
            format!("{{host: '*.amazonaws.com', methods: {ALL}}}"),
            format!("{{host: api.anthropic.com, methods: {ALL}, allow_dangerous: true}}"),
            "{host: registry.npmjs.org}".to_string(),
            format!("{{host: registry.npmjs.org, methods: {ALL}, paths: ['/pub/**']}}"),
            format!("{{host: models.example, methods: {ALL}}}"),
        ];
        let extras = [
            "",
            "\n  forbid: [{host: bad.cdn.example, paths: ['/admin/**']}]",
            "\n  inject: [{host: static.example, header: Authorization, secret: s}]",
            "\n  forbid: [{host: '*.example', paths: ['/x']}]",
        ];
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let (t, r) = (TenantId::single(), RunId("r".into()));
        let mut spliced_checked = 0;
        for zi in 0..200 {
            let n = 1 + zi % 3;
            let reach: Vec<String> = (0..n).map(|_| rng.pick(&rules).clone()).collect();
            let body = format!("  reach: [{}]{}", reach.join(", "), rng.pick(&extras));
            let mut spec = zone(&body);
            if zi % 7 == 0 {
                spec.llm.as_mut().unwrap().upstream = "https://models.example".into();
            }
            let compiled = CompiledZone::new(spec.clone()).unwrap();
            for host in hosts {
                let Inspection::Spliced { .. } = inspection(&spec, host) else { continue };
                assert!(!spec.inject.iter().any(|i| host_matches(&i.host, host)), "{host} spliced with a credential: {body}");
                for _ in 0..60 {
                    let depth = 1 + (rng.0 % 6) as usize;
                    let path: String = (0..depth).map(|_| format!("/{}", rng.pick(&segs))).collect();
                    let query = rng.pick(&queries);
                    for m in HTTP_METHODS {
                        let op = Op::egress_with_query(&t, &r, "z", m, host, &path, query);
                        let v = compiled.evaluate(&op);
                        assert!(matches!(v, Verdict::AllowByReach(_)), "{host} is spliced but {m} {path}?{query} is {v:?} in {body}");
                        spliced_checked += 1;
                    }
                }
            }
        }
        assert!(spliced_checked > 10_000, "the property was exercised ({spliced_checked} requests)");
    }

    /// `RISK_HOSTS` is complete: the dangerous-pattern list raises risk past R2 for no other host.
    #[test]
    fn risk_is_raised_only_for_risk_hosts() {
        let segs = ["repos", "o", "r", "graphql", "hooks", "merge", "contents", ".github", "git", "refs", "info", "git-receive-pack", "x"];
        let mut rng = Rng(42);
        let (t, r) = (TenantId::single(), RunId("r".into()));
        for host in
            ["static.example", "github.com.evil.example", "evilgithub.com", "gitlab.com", "registry.npmjs.org", "amazonaws.com.example"]
        {
            for _ in 0..500 {
                let path: String = (0..1 + (rng.0 % 6) as usize).map(|_| format!("/{}", rng.pick(&segs))).collect();
                for m in HTTP_METHODS {
                    let op = Op::egress_with_query(&t, &r, "z", m, host, &path, "service=git-receive-pack");
                    assert!(op.risk <= RiskClass::R2WriteReversible, "{m} {host}{path} is {:?}", op.risk);
                }
            }
        }
        // And for the risk hosts it can be raised (so the list isn't stale the other way).
        for (m, host, path) in
            [("POST", "github.com", "/o/r.git/git-receive-pack"), ("POST", "api.github.com", "/graphql"), ("GET", "s3.amazonaws.com", "/")]
        {
            assert!(Op::egress(&t, &r, "z", m, host, path).risk >= RiskClass::R3ExternalOrIrreversible, "{host}");
        }
    }

    #[test]
    fn the_view_lists_each_reach_host_once() {
        let z = zone(&format!(
            "  reach:\n    - {{host: static.example, methods: {ALL}}}\n    - {{host: static.example}}\n    - {{host: api.github.com}}\n  forbid: [{{host: api.github.com, paths: ['/admin/**']}}]"
        ));
        let v = view(&z);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], ("static.example".into(), Inspection::Spliced { rule: 0 }));
        assert!(matches!(&v[1].1, Inspection::Inspected(why) if why.contains("forbid")), "{v:?}");
    }

    /// #573: what a box needs of its node's CA: its inspected hosts only, wildcards as subtrees,
    /// nothing a wider entry covers; and what a CA's list leaves uncovered.
    #[test]
    fn a_box_needs_its_inspected_hosts_of_its_node_ca() {
        let z: ZoneSpec = crate::yaml::from_str(concat!(
            "name: z\n",
            "reach:\n",
            "  - { host: api.github.com, methods: [GET], paths: ['/repos/**'] }\n",
            "  - { host: '*.example.org', methods: [GET], paths: ['/x/**'] }\n",
            "  - { host: a.example.org, methods: [GET], paths: ['/x/**'] }\n",
            "  - { host: wide.test, methods: [GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE], paths: ['/**'] }\n",
            "  - { host: localhost, methods: [GET], paths: ['/**'] }\n",
        ))
        .unwrap();
        // wide.test is spliced (wholesale), localhost never reachable, a.example.org under .example.org.
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(ca_hosts(&z, &[]), s(&[".example.org", "api.github.com"]));
        assert_eq!(ca_hosts(&z, &["Late.Test.".into()]), s(&[".example.org", "api.github.com", "late.test"]));
        assert_eq!(uncovered(&s(&["api.github.com"]), &ca_hosts(&z, &[])), s(&[".example.org"]));
        // An exact entry covers its names; `.d` only what is under d.
        assert!(uncovered(&s(&["example.org"]), &s(&[".example.org", "a.example.org", "example.org"])).is_empty());
        assert_eq!(uncovered(&s(&[".example.org"]), &s(&["example.org", "a.example.org"])), s(&["example.org"]));
        assert!(uncovered(&s(&[".org"]), &s(&[".example.org", "x.example.org"])).is_empty());
        assert_eq!(uncovered(&s(&["a.example.org"]), &s(&["example.org", ".example.org"])), s(&["example.org", ".example.org"]));
        assert!(uncovered(&s(&["*"]), &s(&["anything.test", ".any.test"])).is_empty());
        // As a verifier reads it.
        assert!(subtree_permits("api.example.com", "x.api.example.com") && !subtree_permits(".example.org", "example.org"));
    }
}

#[cfg(kani)]
#[path = "proofs/splice.rs"]
mod proofs;
