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

use crate::manifest::{host_matches, ZoneSpec};
use crate::op::{never_reachable, HTTP_METHODS};

/// Hosts (and host patterns) for which the dangerous-pattern list (`op::classify`) can rate a
/// request R3 or higher. For these, a reach rule allows every request only with `allow_dangerous`.
/// The property test in this module checks that `classify` raises risk for no other host.
pub const RISK_HOSTS: &[&str] = &["github.com", "api.github.com", "*.amazonaws.com", "metadata.google.internal", "169.254.169.254"];

/// The model provider's host: its calls go through the model proxy's budget and checks, so it is
/// always inspected.
pub const MODEL_HOST: &str = "api.anthropic.com";

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
/// `b`, this is [`host_matches`]`(a, b)`.
pub fn patterns_overlap(a: &str, b: &str) -> bool {
    let a = a.trim_end_matches('.').to_ascii_lowercase();
    let b = b.trim_end_matches('.').to_ascii_lowercase();
    match (a.strip_prefix("*."), b.strip_prefix("*.")) {
        (None, None) => a == b,
        (Some(_), None) => host_matches(&a, &b),
        (None, Some(_)) => host_matches(&b, &a),
        // Two wildcards share names when one suffix is the other or lies under it.
        (Some(s), Some(t)) => s == t || s.ends_with(&format!(".{t}")) || t.ends_with(&format!(".{s}")),
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

/// The model hosts of a zone: the provider's own host, and the zone's model upstream if it names
/// another one.
fn model_hosts(zone: &ZoneSpec) -> Vec<String> {
    let mut hosts = vec![MODEL_HOST.to_string()];
    if let Some(h) = zone.llm.as_ref().and_then(|l| url::Url::parse(&l.upstream).ok()).and_then(|u| u.host_str().map(str::to_string)) {
        hosts.push(h.to_ascii_lowercase());
    }
    hosts
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::op::{CompiledZone, Op, Verdict};
    use crate::{Manifest, RiskClass, RunId, TenantId};

    fn zone(body: &str) -> ZoneSpec {
        Manifest::from_yaml(&format!("task: t\nagent: {{name: a}}\nzone:\n  name: z\n  llm: {{}}\n{body}")).unwrap().zone
    }

    const ALL: &str = "[GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE]";

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
        assert!(!spliced(&format!("  reach: [{{host: api.anthropic.com, methods: {ALL}, allow_dangerous: true}}]"), "api.anthropic.com"));
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
            "repos", "o", "r", "graphql", "hooks", "merge", "merges", "actions", "contents", ".github", "git", "refs", "info",
            "git-receive-pack", "git-upload-pack", "pulls", "1", "update-branch", "keys", "secrets", "comments", "admin", "issues",
            "collaborators", "dispatches", "releases", "x",
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
        for host in ["static.example", "github.com.evil.example", "evilgithub.com", "gitlab.com", "registry.npmjs.org", "amazonaws.com.example"] {
            for _ in 0..500 {
                let path: String = (0..1 + (rng.0 % 6) as usize).map(|_| format!("/{}", rng.pick(&segs))).collect();
                for m in HTTP_METHODS {
                    let op = Op::egress_with_query(&t, &r, "z", m, host, &path, "service=git-receive-pack");
                    assert!(op.risk <= RiskClass::R2WriteReversible, "{m} {host}{path} is {:?}", op.risk);
                }
            }
        }
        // And for the risk hosts it can be raised (so the list isn't stale the other way).
        for (m, host, path) in [("POST", "github.com", "/o/r.git/git-receive-pack"), ("POST", "api.github.com", "/graphql"), ("GET", "s3.amazonaws.com", "/")] {
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
}
