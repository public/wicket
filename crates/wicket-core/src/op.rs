//! `Op`: the normalised form of every boundary crossing, its risk class, and the pure decision.

use crate::manifest::{compile_glob, fold_case_glob, host_matches, ManifestError, ZoneSpec};
use crate::{RunId, TenantId};
use globset::GlobMatcher;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskClass {
    R0Read,
    R1ReadScoped,
    R2WriteReversible,
    R3ExternalOrIrreversible,
    R4ExecOrPrivilege,
}

impl RiskClass {
    /// 0 (R0) to 4 (R4), as the ledger stores a grant's risk bound.
    pub fn rank(self) -> i64 {
        self as i64
    }

    /// The class named as `{:?}` prints it (`R2WriteReversible`).
    pub fn from_name(name: &str) -> Option<RiskClass> {
        use RiskClass::*;
        [R0Read, R1ReadScoped, R2WriteReversible, R3ExternalOrIrreversible, R4ExecOrPrivilege]
            .into_iter()
            .find(|r| format!("{r:?}") == name)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Surface {
    Egress,
    Llm,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Op {
    pub tenant: TenantId,
    pub run: RunId,
    pub zone: String,
    pub surface: Surface,
    pub method: String,
    pub host: String,
    /// Canonical path, no query.
    pub path: String,
    pub risk: RiskClass,
    /// Why the risk is what it is (dangerous-pattern ids).
    pub effects: Vec<String>,
}

impl Op {
    /// Builds an egress op and classifies its risk.
    pub fn egress(tenant: &TenantId, run: &RunId, zone: &str, method: &str, host: &str, path: &str) -> Op {
        Self::egress_with_query(tenant, run, zone, method, host, path, "")
    }

    /// As [`Op::egress`], with the query string available to the dangerous-pattern list (it is not
    /// part of what a grant binds to).
    pub fn egress_with_query(tenant: &TenantId, run: &RunId, zone: &str, method: &str, host: &str, path: &str, query: &str) -> Op {
        let method = method.to_ascii_uppercase();
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let (risk, effects) = classify(&method, &host, path, query);
        Op {
            tenant: tenant.clone(),
            run: run.clone(),
            zone: zone.to_string(),
            surface: Surface::Egress,
            method,
            host,
            path: path.to_string(),
            risk,
            effects,
        }
    }

    /// What a grant binds to: tenant, zone, method, host and path.
    pub fn digest(&self) -> String {
        let mut h = Sha256::new();
        for part in [&self.tenant.0, &self.zone, &self.method, &self.host, &self.path] {
            h.update(part.as_bytes());
            h.update([0u8]);
        }
        hex::encode(&h.finalize()[..16])
    }
}

/// A small, hand-maintained dangerous-pattern list (design §10). It can only raise risk.
///
/// GitHub endpoints are matched on the path's segments, lowercased (GitHub folds the case of owner
/// and repository names, and lowercasing can only make more paths match, which only raises risk).
/// Paths reach here canonical (`canonical_path`): no escapes of unreserved characters, no `;`, no
/// dot segments, so a segment is spelled one way.
fn classify(method: &str, host: &str, path: &str, query: &str) -> (RiskClass, Vec<String>) {
    let mut risk = match method {
        "GET" | "HEAD" | "OPTIONS" => RiskClass::R1ReadScoped,
        _ => RiskClass::R2WriteReversible,
    };
    let mut effects = Vec::new();
    let mut raise = |r: RiskClass, why: &str, risk: &mut RiskClass| {
        if r > *risk {
            *risk = r;
        }
        effects.push(why.to_string());
    };
    let lower = path.to_ascii_lowercase();
    let segs: Vec<&str> = lower.split('/').filter(|s| !s.is_empty()).collect();
    let has = |names: &[&str]| segs.iter().any(|s| names.contains(s));
    if host == "github.com" {
        // Ref discovery is a read only for exactly the upload-pack (fetch) service: any other query
        // (receive-pack, or an escaped or repeated spelling of it) is treated as a push.
        let discovery = lower.ends_with("/info/refs") && !(query.is_empty() || query == "service=git-upload-pack");
        if lower.ends_with("/git-receive-pack") || discovery {
            raise(RiskClass::R4ExecOrPrivilege, "gh.git_push: pushes can trigger CI", &mut risk);
        }
    }
    if host == "api.github.com" && risk >= RiskClass::R2WriteReversible {
        // `/repos/{owner}/{repo}/...`: what follows the repository.
        let rest: &[&str] = if segs.first() == Some(&"repos") && segs.len() >= 3 { &segs[3..] } else { &[] };
        if segs.first() == Some(&"graphql") {
            raise(RiskClass::R4ExecOrPrivilege, "gh.graphql: a GraphQL mutation can do anything the token can", &mut risk);
        }
        if segs.first() == Some(&"repos") && segs.len() == 3 {
            raise(RiskClass::R4ExecOrPrivilege, "gh.repo_settings: changes or deletes the repository", &mut risk);
        }
        if rest.starts_with(&["contents", ".github"]) {
            raise(RiskClass::R4ExecOrPrivilege, "gh.workflow_path: edits CI with the repo's secrets", &mut risk);
        }
        // Blobs, trees and commits made through the git data API do nothing until a ref points at
        // them; moving the ref is what lands a change (a workflow edit included), as a push does.
        if rest.starts_with(&["git", "refs"]) {
            raise(RiskClass::R4ExecOrPrivilege, "gh.git_ref: moves a branch or tag, as a push does", &mut risk);
        }
        let update_branch = rest.first() == Some(&"pulls") && rest.get(2) == Some(&"update-branch");
        if has(&["merge", "merges", "merge-upstream", "dispatches", "actions", "deployments"]) || update_branch {
            raise(RiskClass::R4ExecOrPrivilege, "gh.exec: merges, updates branches or runs workflows", &mut risk);
        }
        let perms = [
            "collaborators",
            "invitations",
            "keys",
            "gpg_keys",
            "ssh_signing_keys",
            "hooks",
            "secrets",
            "variables",
            "environments",
            "protection",
            "rulesets",
            "transfer",
            "members",
            "memberships",
        ];
        if has(&perms) {
            raise(RiskClass::R4ExecOrPrivilege, "gh.perm_manage: changes access or credentials", &mut risk);
        }
        if has(&["comments", "reviews", "releases"]) || lower.ends_with("/issues") || lower.ends_with("/pulls") {
            raise(RiskClass::R3ExternalOrIrreversible, "gh.notify: posts visible content", &mut risk);
        }
    }
    if host.ends_with(".amazonaws.com") || host == "metadata.google.internal" || host == "169.254.169.254" {
        raise(RiskClass::R4ExecOrPrivilege, "cloud: cloud API or metadata endpoint", &mut risk);
    }
    (risk, effects)
}

/// The pure part of a decision. The ledger (grants, use counts) is consulted only on `NeedsGrant`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// Allowed by reach rule `n` of the zone.
    AllowByReach(usize),
    /// Never allowed, whatever the ledger says.
    Forbidden(String),
    /// Outside reach, or too risky for reach alone: allowed only with a live grant.
    NeedsGrant(String),
}

const FORBIDDEN_HOSTS: &[&str] = &["169.254.169.254", "metadata.google.internal", "metadata", "100.100.100.200"];

/// What a host is to a zone, before any request to it: decided when the box asks to connect.
#[derive(Debug, PartialEq, Eq)]
pub enum HostVerdict {
    /// Requests to it are evaluated one by one.
    Open,
    /// Never reachable: refuse the connection, saying so.
    Forbidden(String),
    /// Not named by the zone, which hides such hosts: behave as if it doesn't exist.
    Hidden,
}

/// Why `host` is never reachable from a sandbox, whatever the zone says: metadata endpoints,
/// localhost and non-public addresses. `None` for every other host.
///
/// The host is parsed as a URL parser would (WHATWG host parsing, as the `url` crate and browsers
/// do), so every spelling of an address is judged as that address: `2852039166`, `0xa9fea9fe`,
/// `0251.0376.0251.0376`, `169.254.169.254.` and `[::ffff:a9fe:a9fe]` are all 169.254.169.254. A
/// host that doesn't parse is never reachable either. This is the name check; the address a name
/// resolves to is checked again when wicket dials it (wicket-proxy).
pub fn never_reachable(host: &str) -> Option<String> {
    let parsed = match url::Host::parse(host) {
        Ok(h) => h,
        Err(e) => return Some(format!("{host:?} is not a valid host ({e})")),
    };
    let ip = match parsed {
        url::Host::Ipv4(v4) => std::net::IpAddr::V4(v4),
        url::Host::Ipv6(v6) => std::net::IpAddr::V6(v6),
        url::Host::Domain(d) => {
            let d = d.trim_end_matches('.');
            if FORBIDDEN_HOSTS.contains(&d) || d == "localhost" || d.ends_with(".localhost") {
                return Some(format!("host {d} is never reachable from a sandbox"));
            }
            // wicket's own name: the box reaches it directly (NO_PROXY), never as an egress target, and
            // its approval namespace (SPAWN, LINK, CAPACITY) is wicket's alone (#117).
            if is_wicket_host(d) {
                return Some(format!("host {d} is wicket's own: it is never an egress target"));
            }
            return None;
        }
    };
    (!is_public_ip(&ip)).then(|| format!("non-public address {ip}"))
}

/// Methods wicket uses for its own approvals, on host [`crate::link::DOMAIN`]: starting a box beyond
/// its parent's zone, a link beyond the default policy, and a capacity lease.
pub const RESERVED_METHODS: &[&str] = &["SPAWN", "LINK", "CAPACITY"];

/// The HTTP methods an agent may ask a human for (request_access) or a node may raise a request for.
pub const HTTP_METHODS: &[&str] = &["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"];

/// `wicket.internal` and every name under it (the in-box address of wicket's services and the link
/// names of other boxes).
pub fn is_wicket_host(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    h == crate::link::DOMAIN || h.ends_with(&format!(".{}", crate::link::DOMAIN))
}

impl Op {
    /// Whether this op is in wicket's own approval namespace (#117): a reserved method, or a wicket
    /// host. Only wicket raises such requests; an agent or a node never may.
    pub fn is_reserved(&self) -> bool {
        is_wicket_host(&self.host) || RESERVED_METHODS.contains(&self.method.to_ascii_uppercase().as_str())
    }

    /// Why an agent or a node may not raise a request for this op, if it may not: a reserved op, or
    /// a method that isn't one of [`HTTP_METHODS`].
    pub fn refused_for_agents(&self) -> Option<String> {
        if self.is_reserved() {
            return Some(format!("{} {} is wicket's own approval namespace: only wicket asks for it", self.method, self.host));
        }
        if !HTTP_METHODS.contains(&self.method.as_str()) {
            return Some(format!("method {:?} is not one of {}", self.method, HTTP_METHODS.join(", ")));
        }
        None
    }
}

pub fn host_verdict(zone: &ZoneSpec, host: &str) -> HostVerdict {
    if let Some(why) = never_reachable(host) {
        return HostVerdict::Forbidden(why);
    }
    if zone.forbid.iter().any(|f| f.covers_host(host)) {
        return HostVerdict::Forbidden(format!("host {host} is forbidden in this zone"));
    }
    if zone.unlisted_hosts == crate::manifest::UnlistedHosts::Hide && !zone.reach.iter().any(|r| r.host_matches(host)) {
        return HostVerdict::Hidden;
    }
    HostVerdict::Open
}

/// A zone with its path globs compiled once, so a decision costs a few matches rather than compiling
/// globs on every request. A run's zone doesn't change while it runs (grants live in the ledger), so
/// the run builds one when it starts and every proxy shares it. It dereferences to the `ZoneSpec`.
pub struct CompiledZone {
    spec: ZoneSpec,
    /// Per forbid rule, its path matchers (same order as `spec.forbid`).
    forbid: Vec<Vec<GlobMatcher>>,
    /// Per reach rule, its path matchers (same order as `spec.reach`).
    reach: Vec<Vec<GlobMatcher>>,
}

impl CompiledZone {
    /// Compiles every glob. A glob that doesn't compile is an error, never "doesn't match", so a broken
    /// forbid rule can't silently allow.
    pub fn new(spec: ZoneSpec) -> Result<Self, ManifestError> {
        let globs = |paths: &[String]| paths.iter().map(|p| compile_glob(p)).collect::<Result<Vec<_>, _>>();
        // Forbid globs ignore ASCII case (see `ForbidRule::paths`). A glob that doesn't compile is
        // reported as written.
        let forbid = spec
            .forbid
            .iter()
            .map(|f| f.paths.iter().map(|p| compile_glob(p).and_then(|_| compile_glob(&fold_case_glob(p)))).collect::<Result<Vec<_>, _>>())
            .collect::<Result<_, _>>()?;
        let reach = spec.reach.iter().map(|r| globs(&r.paths)).collect::<Result<_, _>>()?;
        Ok(Self { spec, forbid, reach })
    }

    pub fn spec(&self) -> &ZoneSpec {
        &self.spec
    }

    /// Whether a connection to `host` may be opened at all (see `host_verdict`).
    pub fn host_verdict(&self, host: &str) -> HostVerdict {
        host_verdict(&self.spec, host)
    }

    /// The decision for one request: forbidden outright, allowed by reach, or needing a grant.
    ///
    /// Reach rules are a set, not an ordered list: a request is allowed by reach if *some* rule that
    /// matches its host, method and path allows it (its risk is R2 or lower, or the rule has
    /// `allow_dangerous`), and the verdict names the first such rule. A request that only matches rules
    /// without `allow_dangerous`, or matches none, needs a grant. Order-independence is what lets the
    /// same zone be written as Biscuit checks (wicket-authz), where alternatives have no order.
    pub fn evaluate(&self, op: &Op) -> Verdict {
        let zone = &self.spec;
        if let Some(why) = never_reachable(&op.host) {
            return Verdict::Forbidden(why);
        }
        let forbidden = zone
            .forbid
            .iter()
            .zip(&self.forbid)
            .any(|(f, globs)| host_matches(&f.host, &op.host) && globs.iter().any(|g| g.is_match(&op.path)));
        if forbidden {
            return Verdict::Forbidden(format!("{} {}{} is forbidden in this zone", op.method, op.host, op.path));
        }
        let risky = op.risk >= RiskClass::R3ExternalOrIrreversible;
        let mut first_match = None;
        for (i, (rule, globs)) in zone.reach.iter().zip(&self.reach).enumerate() {
            if !rule.host_matches(&op.host) {
                continue;
            }
            if !rule.methods.iter().any(|m| m.eq_ignore_ascii_case(&op.method)) {
                continue;
            }
            if !globs.iter().any(|g| g.is_match(&op.path)) {
                continue;
            }
            if !risky || rule.allow_dangerous {
                return Verdict::AllowByReach(i);
            }
            first_match.get_or_insert(i);
        }
        match first_match {
            Some(i) => Verdict::NeedsGrant(format!("matches reach rule {i} but is {:?}: {}", op.risk, op.effects.join("; "))),
            None => Verdict::NeedsGrant(format!("{} {}{} is outside the zone's reach", op.method, op.host, op.path)),
        }
    }
}

impl std::ops::Deref for CompiledZone {
    type Target = ZoneSpec;
    fn deref(&self) -> &ZoneSpec {
        &self.spec
    }
}

/// One decision against a zone that isn't compiled yet: compiles it first, so it's slow. Callers on the
/// request path hold a `CompiledZone`. A zone whose globs don't compile forbids everything.
pub fn evaluate(zone: &ZoneSpec, op: &Op) -> Verdict {
    match CompiledZone::new(zone.clone()) {
        Ok(z) => z.evaluate(op),
        Err(e) => Verdict::Forbidden(format!("this zone's policy is invalid: {e}")),
    }
}

/// Whether an address is on the public internet: not private, loopback, link-local, CGNAT,
/// multicast, reserved, documentation or benchmarking space, and not an IPv6 form that carries or
/// translates to an IPv4 address (mapped, compatible, NAT64, 6to4, Teredo), which a gateway could
/// turn into a private one.
pub fn is_public_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || (o[0] == 192 && o[1] == 0 && (o[2] == 0 || o[2] == 2))
                || (o[0] == 192 && o[1] == 88 && o[2] == 99)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113))
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xffc0) == 0xfec0
                || v6.to_ipv4_mapped().is_some()
                || s[..6] == [0; 6]
                || (s[0] == 0x64 && s[1] == 0xff9b)
                || s[0] == 0x2002
                || (s[0] == 0x2001 && s[1] < 0x0200)
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x0100 && s[1..4] == [0; 3]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Manifest;

    fn zone() -> ZoneSpec {
        Manifest::from_yaml(
            r#"
task: t
agent: { name: a }
zone:
  name: z
  reach:
    - { host: api.github.com, paths: ["/repos/octocat/hello/**"] }
    - { host: api.github.com, methods: [PUT], paths: ["/repos/octocat/hello/contents/**"] }
    - { host: github.com, methods: [GET, POST], paths: ["/octocat/hello.git/info/refs", "/octocat/hello.git/git-upload-pack", "/octocat/hello.git/git-receive-pack"] }
  llm: {}
"#,
        )
        .unwrap()
        .zone
    }

    fn op(m: &str, h: &str, p: &str) -> Op {
        Op::egress(&TenantId::single(), &RunId("run_test".into()), "z", m, h, p)
    }

    /// #117: wicket's own host is never an egress target, and its approval methods are reserved.
    #[test]
    fn wickets_own_namespace_is_reserved() {
        for h in ["wicket.internal", "WICKET.internal.", "narrow.wicket.internal"] {
            assert!(never_reachable(h.to_ascii_lowercase().trim_end_matches('.')).is_some(), "{h}");
            assert!(is_wicket_host(h), "{h}");
        }
        assert!(never_reachable("wicket.internal.example.com").is_none());
        let (t, r) = (TenantId::single(), RunId("r".into()));
        let op = |m: &str, h: &str| Op::egress(&t, &r, "z", m, h, "/");
        assert!(op("spawn", "api.example.com").is_reserved());
        assert!(op("GET", "wicket.internal").is_reserved());
        assert!(op("GET", "api.example.com").refused_for_agents().is_none());
        assert!(op("PROPFIND", "api.example.com").refused_for_agents().is_some());
        assert!(op("GET /x HTTP/1.1\r\n", "api.example.com").refused_for_agents().is_some());
    }

    #[test]
    fn reads_in_reach_are_allowed() {
        assert_eq!(evaluate(&zone(), &op("GET", "api.github.com", "/repos/octocat/hello/readme")), Verdict::AllowByReach(0));
        assert_eq!(evaluate(&zone(), &op("POST", "github.com", "/octocat/hello.git/git-upload-pack")), Verdict::AllowByReach(2));
    }

    #[test]
    fn single_star_does_not_cross_segments() {
        let z = Manifest::from_yaml("task: t\nagent: {name: a}\nzone: {name: z, reach: [{host: h.example, paths: ['/a/*']}], llm: {}}")
            .unwrap()
            .zone;
        assert_eq!(evaluate(&z, &op("GET", "h.example", "/a/b")), Verdict::AllowByReach(0));
        assert!(matches!(evaluate(&z, &op("GET", "h.example", "/a/b/c")), Verdict::NeedsGrant(_)));
    }

    #[test]
    fn outside_reach_needs_grant() {
        assert!(matches!(evaluate(&zone(), &op("GET", "api.github.com", "/repos/other/repo")), Verdict::NeedsGrant(_)));
        assert!(matches!(evaluate(&zone(), &op("GET", "example.com", "/")), Verdict::NeedsGrant(_)));
    }

    #[test]
    fn dangerous_patterns_override_reach() {
        let push = op("POST", "github.com", "/octocat/hello.git/git-receive-pack");
        assert_eq!(push.risk, RiskClass::R4ExecOrPrivilege);
        assert!(matches!(evaluate(&zone(), &push), Verdict::NeedsGrant(_)));
        let wf = op("PUT", "api.github.com", "/repos/octocat/hello/contents/.github/workflows/ci.yml");
        assert!(matches!(evaluate(&zone(), &wf), Verdict::NeedsGrant(_)));
        let ok = op("PUT", "api.github.com", "/repos/octocat/hello/contents/README.md");
        assert_eq!(evaluate(&zone(), &ok), Verdict::AllowByReach(1));
    }

    #[test]
    fn push_discovery_is_a_push() {
        let o = Op::egress_with_query(
            &TenantId::single(),
            &RunId("r".into()),
            "z",
            "GET",
            "github.com",
            "/octocat/hello.git/info/refs",
            "service=git-receive-pack",
        );
        assert_eq!(o.risk, RiskClass::R4ExecOrPrivilege);
        let r = Op::egress_with_query(
            &TenantId::single(),
            &RunId("r".into()),
            "z",
            "GET",
            "github.com",
            "/octocat/hello.git/info/refs",
            "service=git-upload-pack",
        );
        assert_eq!(r.risk, RiskClass::R1ReadScoped);
    }

    #[test]
    fn metadata_and_private_addresses_are_forbidden() {
        assert!(matches!(evaluate(&zone(), &op("GET", "169.254.169.254", "/latest")), Verdict::Forbidden(_)));
        assert!(matches!(evaluate(&zone(), &op("GET", "10.0.0.1", "/")), Verdict::Forbidden(_)));
        assert!(matches!(evaluate(&zone(), &op("GET", "localhost", "/")), Verdict::Forbidden(_)));
    }

    /// #116: every spelling of a non-public address is that address.
    #[test]
    fn every_spelling_of_a_non_public_address_is_refused() {
        for h in [
            "2852039166",
            "0xa9fea9fe",
            "0251.0376.0251.0376",
            "169.254.169.254.",
            "169.254.43518",
            "[::1]",
            "[::ffff:127.0.0.1]",
            "[::ffff:a9fe:a9fe]",
            "[::a9fe:a9fe]",
            "[64:ff9b::a9fe:a9fe]",
            "[2002:a9fe:a9fe::]",
            "[2001:0:4136:e378:8000:63bf:3fff:fdd2]",
            "[ff02::1]",
            "[fec0::1]",
            "0xe0000001",
            "240.0.0.1",
            "192.0.2.1",
            "0x7f.1",
            "metadata.",
            "METADATA.GOOGLE.INTERNAL",
            "LocalHost",
            "foo.localhost.",
            "a b",
            "foo.123",
        ] {
            assert!(never_reachable(h).is_some(), "{h}");
            assert!(matches!(evaluate(&zone(), &op("GET", h, "/")), Verdict::Forbidden(_)), "{h}");
        }
        for h in ["example.com", "api.github.com", "1.1.1.1", "[2606:4700::1111]"] {
            assert_eq!(never_reachable(h), None, "{h}");
        }
    }

    #[test]
    fn digest_binds_method_host_path() {
        let a = op("GET", "api.github.com", "/x");
        let b = op("POST", "api.github.com", "/x");
        assert_ne!(a.digest(), b.digest());
        assert_eq!(a.digest(), op("GET", "API.github.com", "/x").digest());
    }

    #[test]
    fn forbid_rules_win_over_reach_and_never_escalate() {
        let m = Manifest::from_yaml("task: t\nagent: { name: a }\nzone:\n  name: z\n  llm: {}\n  reach: [{ host: api.example.com, methods: [GET, POST], paths: [\"/**\"] }]\n  forbid: [{ host: api.example.com, paths: [\"/v1/mcp_servers\"] }, { host: mcp.example.com }]\n").unwrap();
        let t = TenantId::single();
        let r = RunId("run_x".into());
        let op = |host: &str, path: &str| Op::egress(&t, &r, "z", "GET", host, path);
        assert!(matches!(evaluate(&m.zone, &op("api.example.com", "/v1/mcp_servers")), Verdict::Forbidden(_)));
        assert!(matches!(evaluate(&m.zone, &op("mcp.example.com", "/anything")), Verdict::Forbidden(_)));
        assert!(matches!(evaluate(&m.zone, &op("api.example.com", "/v1/messages")), Verdict::AllowByReach(0)));
    }

    /// #143: npm's `@scope%2fname` is decided as `/@scope/name`, so rules on the decoded path
    /// apply to it as to the unencoded spelling, forbids included.
    #[test]
    fn npm_scoped_packages_are_decided_decoded() {
        let m = Manifest::from_yaml("task: t\nagent: { name: a }\nzone:\n  name: z\n  llm: {}\n  reach: [{ host: registry.npmjs.org, methods: [GET], paths: [\"/**\"] }]\n  forbid: [{ host: registry.npmjs.org, paths: [\"/@evil/**\", \"/@types/secret\"] }]\n").unwrap();
        let t = TenantId::single();
        let r = RunId("run_x".into());
        let decide = |raw: &str| {
            let path = crate::canonical_path(raw).unwrap();
            evaluate(&m.zone, &Op::egress(&t, &r, "z", "GET", "registry.npmjs.org", &path))
        };
        for p in ["/@evil%2fpkg", "/@evil%2Fpkg", "/@evil%2fpkg/1.0.0", "/@evil/pkg", "/@types%2fsecret", "/@EVIL%2fpkg"] {
            match crate::canonical_path(p) {
                Ok(_) => assert!(matches!(decide(p), Verdict::Forbidden(_)), "{p}"),
                Err(_) => assert_eq!(p, "/@EVIL%2fpkg", "only the upper-case scope is refused outright"),
            }
        }
        for p in ["/@types%2fnode", "/@types/node", "/@babel%2fcore/7.0.0"] {
            assert!(matches!(decide(p), Verdict::AllowByReach(0)), "{p}");
        }
        assert_eq!(
            Op::egress(&t, &r, "z", "GET", "registry.npmjs.org", &crate::canonical_path("/@types%2fnode").unwrap()).digest(),
            Op::egress(&t, &r, "z", "GET", "registry.npmjs.org", "/@types/node").digest(),
            "both spellings are one op, so one grant covers both"
        );
    }

    #[test]
    fn hosts_are_judged_before_any_request() {
        let z = |extra: &str| {
            Manifest::from_yaml(&format!("task: t\nagent: {{ name: a }}\nzone:\n  name: z\n  llm: {{}}\n  reach: [{{ host: api.example.com }}, {{ host: \"*.cdn.example\" }}]\n  forbid: [{{ host: mcp.example.com }}, {{ host: api.example.com, paths: [\"/private/**\"] }}]\n{extra}")).unwrap().zone
        };
        let open = z("");
        assert_eq!(host_verdict(&open, "api.example.com"), HostVerdict::Open);
        assert_eq!(host_verdict(&open, "news.example.org"), HostVerdict::Open, "escalate is the default");
        assert!(matches!(host_verdict(&open, "mcp.example.com"), HostVerdict::Forbidden(_)));
        assert!(matches!(host_verdict(&open, "169.254.169.254"), HostVerdict::Forbidden(_)));
        assert!(matches!(host_verdict(&open, "10.0.0.1"), HostVerdict::Forbidden(_)));
        let hidden = z("  unlisted_hosts: hide\n");
        assert_eq!(host_verdict(&hidden, "news.example.org"), HostVerdict::Hidden);
        assert_eq!(host_verdict(&hidden, "a.cdn.example"), HostVerdict::Open);
        assert_eq!(host_verdict(&hidden, "api.example.com"), HostVerdict::Open, "a path-limited forbid doesn't hide the host");
    }

    /// The decision with globs compiled on every call: the oracle `CompiledZone::evaluate` must agree
    /// with. It follows the same reach semantics (some matching rule that allows the risk decides;
    /// see `CompiledZone::evaluate`), written independently as "collect every matching rule, then
    /// pick", so the test checks that compiling globs once changes nothing. Before reach rules became
    /// order-independent this oracle let the first matching rule decide; the only decisions that
    /// changed are R3+ requests whose first matching rule lacks `allow_dangerous` while a later one
    /// has it (`a_later_dangerous_rule_allows_what_an_earlier_rule_matches`).
    fn evaluate_uncompiled(zone: &ZoneSpec, op: &Op) -> Verdict {
        if let Some(why) = never_reachable(&op.host) {
            return Verdict::Forbidden(why);
        }
        if zone.forbid.iter().any(|f| f.matches(&op.host, &op.path)) {
            return Verdict::Forbidden(format!("{} {}{} is forbidden in this zone", op.method, op.host, op.path));
        }
        let matching: Vec<usize> = (0..zone.reach.len())
            .filter(|&i| {
                let rule = &zone.reach[i];
                rule.host_matches(&op.host)
                    && rule.methods.iter().any(|m| m.eq_ignore_ascii_case(&op.method))
                    && rule.paths.iter().any(|p| compile_glob(p).map(|g| g.is_match(&op.path)).unwrap_or(false))
            })
            .collect();
        let risky = op.risk >= RiskClass::R3ExternalOrIrreversible;
        if let Some(&i) = matching.iter().find(|&&i| !risky || zone.reach[i].allow_dangerous) {
            return Verdict::AllowByReach(i);
        }
        match matching.first() {
            Some(i) => Verdict::NeedsGrant(format!("matches reach rule {i} but is {:?}: {}", op.risk, op.effects.join("; "))),
            None => Verdict::NeedsGrant(format!("{} {}{} is outside the zone's reach", op.method, op.host, op.path)),
        }
    }

    #[test]
    fn a_later_dangerous_rule_allows_what_an_earlier_rule_matches() {
        let z = Manifest::from_yaml("task: t\nagent: { name: a }\nzone:\n  name: z\n  llm: {}\n  reach:\n    - { host: api.github.com, methods: [GET, POST], paths: [\"/repos/acme/**\"] }\n    - { host: api.github.com, methods: [POST], paths: [\"/repos/acme/scratch/**\"], allow_dangerous: true }\n").unwrap().zone;
        // R3 (posts visible content): the first rule matches but isn't dangerous-ok; the second is.
        let o = op("POST", "api.github.com", "/repos/acme/scratch/issues");
        assert_eq!(o.risk, RiskClass::R3ExternalOrIrreversible);
        assert_eq!(evaluate(&z, &o), Verdict::AllowByReach(1));
        // Outside the dangerous rule's paths, only the first rule matches: a grant is needed.
        assert!(matches!(evaluate(&z, &op("POST", "api.github.com", "/repos/acme/api/issues")), Verdict::NeedsGrant(_)));
        // A low-risk request is allowed by the first matching rule.
        assert_eq!(evaluate(&z, &op("POST", "api.github.com", "/repos/acme/scratch/x")), Verdict::AllowByReach(0));
        // Rule order doesn't matter.
        let mut swapped = z.clone();
        swapped.reach.swap(0, 1);
        assert_eq!(evaluate(&swapped, &o), Verdict::AllowByReach(0));
        assert_eq!(evaluate(&swapped, &op("POST", "api.github.com", "/repos/acme/scratch/x")), Verdict::AllowByReach(0));
    }

    /// Paths a glob matches, and near misses: `*` and `**` filled in, the glob's parent, and siblings.
    fn paths_for(glob: &str) -> Vec<String> {
        let fill = |g: &str, one: &str, many: &str| g.replace("**", many).replace('*', one).replace(['{', '}'], "").replace(',', "");
        let mut v = vec![fill(glob, "x", "a/b"), fill(glob, "", "z"), fill(glob, "abc123", "abc123/worker")];
        if let Some((parent, _)) = glob.rsplit_once('/') {
            v.push(format!("{}/", fill(parent, "x", "a")));
            v.push(fill(parent, "x", "a"));
            v.push(format!("{}/other", fill(parent, "x", "a")));
        }
        v.into_iter().map(|p| if p.starts_with('/') { p } else { format!("/{p}") }).collect()
    }

    #[test]
    fn compiled_zones_decide_as_before() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples");
        let files = ["demo.yaml", "hello-github.yaml", "mock-github.yaml", "remote-control/manifest.yaml", "self-hosting/manifest.yaml"];
        let mut zones: Vec<ZoneSpec> =
            files.iter().map(|f| Manifest::from_yaml(&std::fs::read_to_string(format!("{dir}/{f}")).unwrap()).unwrap().zone).collect();
        zones.push(zone());
        zones.push(
            Manifest::from_yaml("task: t\nagent: { name: a }\nzone:\n  name: f\n  llm: {}\n  reach:\n    - { host: \"*.example.com\", methods: [GET, POST], paths: [\"/**\"] }\n    - { host: api.example.com, methods: [PUT, DELETE], paths: [\"/v1/*/items/**\"], allow_dangerous: true }\n  forbid:\n    - { host: api.example.com, paths: [\"/v1/admin/**\", \"/v1/*/secrets\"] }\n    - { host: mcp.example.com }\n")
                .unwrap()
                .zone,
        );
        zones.push(
            Manifest::from_yaml("task: t\nagent: { name: a }\nzone:\n  name: o\n  llm: {}\n  reach:\n    - { host: api.github.com, methods: [GET, POST, PUT], paths: [\"/repos/acme/**\"] }\n    - { host: api.github.com, methods: [POST, PUT], paths: [\"/repos/acme/*/issues\", \"/repos/acme/*/pulls/*/merge\"], allow_dangerous: true }\n")
                .unwrap()
                .zone,
        );
        let (t, r) = (TenantId("t0".into()), RunId("r".into()));
        let (mut checked, mut kinds) = (0, [0usize; 3]);
        for z in &zones {
            let compiled = CompiledZone::new(z.clone()).unwrap();
            let mut hosts: Vec<String> =
                z.reach.iter().map(|x| &x.host).chain(z.forbid.iter().map(|f| &f.host)).map(|h| h.replace("*.", "a.")).collect();
            hosts.extend(["github.com", "api.github.com", "example.com", "169.254.169.254", "localhost"].map(String::from));
            let mut paths: Vec<String> = z
                .reach
                .iter()
                .flat_map(|x| x.paths.iter())
                .chain(z.forbid.iter().flat_map(|f| f.paths.iter()))
                .flat_map(|g| paths_for(g))
                .collect();
            paths.extend(["/", "/x", "/octocat/Hello-World.git/git-receive-pack"].map(String::from));
            // Case-flipped spellings (#115: forbids ignore case, reach doesn't).
            let flipped: Vec<String> = paths.iter().map(|p| p.to_ascii_uppercase()).collect();
            paths.extend(flipped);
            for h in &hosts {
                for p in &paths {
                    for m in ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"] {
                        let op = Op::egress(&t, &r, &z.name, m, h, p);
                        let v = compiled.evaluate(&op);
                        assert_eq!(v, evaluate_uncompiled(z, &op), "zone {} {m} {h}{p}", z.name);
                        kinds[match v {
                            Verdict::AllowByReach(_) => 0,
                            Verdict::Forbidden(_) => 1,
                            Verdict::NeedsGrant(_) => 2,
                        }] += 1;
                        checked += 1;
                    }
                }
            }
        }
        println!("{checked} decisions: {} allowed, {} forbidden, {} need a grant", kinds[0], kinds[1], kinds[2]);
        assert!(checked > 10_000 && kinds.iter().all(|&k| k > 500), "too few decisions of some kind: {kinds:?} of {checked}");
    }

    /// #114: the GitHub endpoints that do what the R4 patterns guard against, spelled any way.
    #[test]
    fn equivalent_github_endpoints_are_classified_alike() {
        let risk = |m: &str, h: &str, p: &str| op(m, h, p).risk;
        use RiskClass::*;
        for (m, p) in [
            ("PATCH", "/repos/acme/app/git/refs/heads/main"),
            ("POST", "/repos/acme/app/git/refs"),
            ("DELETE", "/repos/acme/app/git/refs/tags/v1"),
            ("POST", "/graphql"),
            ("PUT", "/repos/acme/app/pulls/7/update-branch"),
            ("PUT", "/repos/acme/app/pulls/7/merge"),
            ("POST", "/repos/acme/app/merges"),
            ("POST", "/repos/acme/app/merge-upstream"),
            ("PUT", "/repos/ACME/APP/contents/.GITHUB/workflows/ci.yml"),
            ("PUT", "/repos/acme/app/Collaborators/mallory"),
            ("POST", "/repos/acme/app/HOOKS"),
            ("PUT", "/repos/acme/app/branches/main/protection"),
            ("POST", "/repos/acme/app/environments/prod/secrets"),
            ("POST", "/repos/acme/app/transfer"),
            ("DELETE", "/repos/acme/app"),
            ("PATCH", "/repos/acme/app"),
            ("POST", "/user/keys"),
        ] {
            assert_eq!(risk(m, "api.github.com", p), R4ExecOrPrivilege, "{m} {p}");
        }
        // Objects alone change nothing a workflow runs from; reads stay reads.
        assert_eq!(risk("POST", "api.github.com", "/repos/acme/app/git/blobs"), R2WriteReversible);
        assert_eq!(risk("POST", "api.github.com", "/repos/acme/app/git/commits"), R2WriteReversible);
        assert_eq!(risk("GET", "api.github.com", "/repos/acme/app/git/refs/heads/main"), R1ReadScoped);
        assert_eq!(risk("PUT", "api.github.com", "/repos/acme/hooks-docs/contents/README.md"), R2WriteReversible);
        assert_eq!(risk("POST", "api.github.com", "/repos/acme/app/pulls/7/Reviews"), R3ExternalOrIrreversible);
        // git over HTTPS: push in any case, and ref discovery for anything but a plain fetch.
        assert_eq!(risk("POST", "github.com", "/acme/app.git/GIT-RECEIVE-PACK"), R4ExecOrPrivilege);
        let disc = |q: &str| {
            Op::egress_with_query(&TenantId::single(), &RunId("r".into()), "z", "GET", "github.com", "/a/b.git/info/refs", q).risk
        };
        assert_eq!(disc("service=git-upload-pack"), R1ReadScoped);
        assert_eq!(disc(""), R1ReadScoped);
        for q in ["service=git-receive-p%61ck", "service=git-upload-pack&service=git-receive-pack", "service=GIT-RECEIVE-PACK"] {
            assert_eq!(disc(q), R4ExecOrPrivilege, "{q}");
        }
    }

    /// #115: a forbid narrower than reach can't be dodged by spelling the path in another case.
    #[test]
    fn forbids_ignore_case() {
        let z = Manifest::from_yaml("task: t\nagent: { name: a }\nzone:\n  name: z\n  llm: {}\n  reach: [{ host: api.github.com, methods: [GET, PUT], paths: [\"/repos/**\"] }]\n  forbid: [{ host: api.github.com, paths: [\"/repos/acme/prod/**\", \"/repos/[a-c]x/Secret\"] }]\n").unwrap().zone;
        let cz = CompiledZone::new(z.clone()).unwrap();
        for p in [
            "/repos/acme/prod/x",
            "/repos/ACME/prod/x",
            "/repos/acme/PROD/contents/a",
            "/repos/Acme/Prod/x",
            "/repos/BX/secret",
            "/repos/ax/SECRET",
        ] {
            assert!(matches!(cz.evaluate(&op("PUT", "api.github.com", p)), Verdict::Forbidden(_)), "{p}");
            assert!(matches!(evaluate_uncompiled(&z, &op("PUT", "api.github.com", p)), Verdict::Forbidden(_)), "{p}");
        }
        for p in ["/repos/acme/production/x", "/repos/dx/secret", "/repos/ACME/app/x"] {
            assert!(matches!(cz.evaluate(&op("GET", "api.github.com", p)), Verdict::AllowByReach(0)), "{p}");
        }
        // Reach stays case-sensitive.
        assert!(matches!(cz.evaluate(&op("GET", "api.github.com", "/REPOS/x")), Verdict::NeedsGrant(_)));
    }

    #[test]
    fn folded_globs_match_ignoring_case() {
        use crate::manifest::fold_case_glob;
        assert_eq!(fold_case_glob("/a1/*"), "/[aA]1/*");
        assert_eq!(fold_case_glob("/[a-c]/[!x]/\\q/\\*"), "/[A-Ca-c]/[!Xx]/[qQ]/\\*");
        assert_eq!(fold_case_glob("/[a-z_-]"), "/[A-Za-z_-]");
        assert_eq!(fold_case_glob("/[-a]"), "/[-Aa]");
        // Every folded class still compiles, and matches either case.
        for g in ["/[a-z_-]/x", "/[-a]", "/[]a]", "/[!a-c0-9-]", "/[0-9a]", "/[a-]"] {
            assert!(compile_glob(&fold_case_glob(g)).is_ok(), "{g} -> {}", fold_case_glob(g));
        }
        assert!(compile_glob(&fold_case_glob("/[a-z_-]/x")).unwrap().is_match("/Q/X"));
        for (g, yes, no) in [
            ("/repos/{acme,octo}/**", "/REPOS/Octo/x", "/repos/other/x"),
            ("/x/[]a]", "/X/A", "/x/b"),
            ("/caf\u{e9}/**", "/CAF\u{e9}/y", "/CAF\u{c9}/y"),
        ] {
            let m = compile_glob(&fold_case_glob(g)).unwrap();
            assert!(m.is_match(yes) && !m.is_match(no), "{g}");
        }
    }

    #[test]
    fn a_zone_with_a_broken_glob_does_not_compile_and_forbids() {
        let mut z = zone();
        z.forbid.push(crate::manifest::ForbidRule { host: "api.github.com".into(), paths: vec!["/a/[".into()] });
        assert!(CompiledZone::new(z.clone()).is_err());
        assert!(matches!(evaluate(&z, &op("GET", "api.github.com", "/repos/octocat/hello/x")), Verdict::Forbidden(_)));
    }
}
