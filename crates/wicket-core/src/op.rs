//! `Op`: the normalised form of every boundary crossing, its risk class, and the pure decision.

use crate::manifest::{compile_glob, ZoneSpec};
use crate::{RunId, TenantId};
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Surface {
    Egress,
    Llm,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    let push_discovery = path.ends_with("/info/refs") && query.split('&').any(|kv| kv == "service=git-receive-pack");
    if host == "github.com" && (path.ends_with("/git-receive-pack") || push_discovery) {
        raise(RiskClass::R4ExecOrPrivilege, "gh.git_push: pushes can trigger CI", &mut risk);
    }
    if host == "api.github.com" && risk >= RiskClass::R2WriteReversible {
        if path.contains("/contents/.github/") {
            raise(RiskClass::R4ExecOrPrivilege, "gh.workflow_path: edits CI with the repo's secrets", &mut risk);
        }
        if path.contains("/merge") || path.ends_with("/dispatches") || path.contains("/actions/") {
            raise(RiskClass::R4ExecOrPrivilege, "gh.exec: merges or dispatches workflows", &mut risk);
        }
        if path.contains("/collaborators") || path.contains("/keys") || path.contains("/hooks") || path.contains("/secrets") {
            raise(RiskClass::R4ExecOrPrivilege, "gh.perm_manage: changes access or credentials", &mut risk);
        }
        if path.contains("/comments") || path.ends_with("/issues") || path.ends_with("/pulls") {
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

pub fn host_verdict(zone: &ZoneSpec, host: &str) -> HostVerdict {
    if FORBIDDEN_HOSTS.contains(&host) || host == "localhost" || host.ends_with(".localhost") {
        return HostVerdict::Forbidden(format!("host {host} is never reachable from a sandbox"));
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if !is_public_ip(&ip) {
            return HostVerdict::Forbidden(format!("non-public address {ip}"));
        }
    }
    if zone.forbid.iter().any(|f| f.covers_host(host)) {
        return HostVerdict::Forbidden(format!("host {host} is forbidden in this zone"));
    }
    if zone.unlisted_hosts == crate::manifest::UnlistedHosts::Hide && !zone.reach.iter().any(|r| r.host_matches(host)) {
        return HostVerdict::Hidden;
    }
    HostVerdict::Open
}

pub fn evaluate(zone: &ZoneSpec, op: &Op) -> Verdict {
    if FORBIDDEN_HOSTS.contains(&op.host.as_str()) || op.host == "localhost" || op.host.ends_with(".localhost") {
        return Verdict::Forbidden(format!("host {} is never reachable from a sandbox", op.host));
    }
    if let Ok(ip) = op.host.parse::<std::net::IpAddr>() {
        if !is_public_ip(&ip) {
            return Verdict::Forbidden(format!("non-public address {ip}"));
        }
    }
    if zone.forbid.iter().any(|f| f.matches(&op.host, &op.path)) {
        return Verdict::Forbidden(format!("{} {}{} is forbidden in this zone", op.method, op.host, op.path));
    }
    for (i, rule) in zone.reach.iter().enumerate() {
        if !rule.host_matches(&op.host) {
            continue;
        }
        if !rule.methods.iter().any(|m| m.eq_ignore_ascii_case(&op.method)) {
            continue;
        }
        let path_ok = rule.paths.iter().any(|p| compile_glob(p).map(|g| g.is_match(&op.path)).unwrap_or(false));
        if !path_ok {
            continue;
        }
        if op.risk >= RiskClass::R3ExternalOrIrreversible && !rule.allow_dangerous {
            return Verdict::NeedsGrant(format!("matches reach rule {i} but is {:?}: {}", op.risk, op.effects.join("; ")));
        }
        return Verdict::AllowByReach(i);
    }
    Verdict::NeedsGrant(format!("{} {}{} is outside the zone's reach", op.method, op.host, op.path))
}

fn is_public_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || o[0] == 0
                || (o[0] == 100 && (64..128).contains(&o[1]))
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)))
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            !(v6.is_loopback() || v6.is_unspecified() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 || v6.to_ipv4_mapped().is_some())
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

    #[test]
    fn reads_in_reach_are_allowed() {
        assert_eq!(evaluate(&zone(), &op("GET", "api.github.com", "/repos/octocat/hello/readme")), Verdict::AllowByReach(0));
        assert_eq!(evaluate(&zone(), &op("POST", "github.com", "/octocat/hello.git/git-upload-pack")), Verdict::AllowByReach(2));
    }

    #[test]
    fn single_star_does_not_cross_segments() {
        let z = Manifest::from_yaml("task: t\nagent: {name: a}\nzone: {name: z, reach: [{host: h.example, paths: ['/a/*']}], llm: {}}").unwrap().zone;
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
        let o = Op::egress_with_query(&TenantId::single(), &RunId("r".into()), "z", "GET", "github.com", "/octocat/hello.git/info/refs", "service=git-receive-pack");
        assert_eq!(o.risk, RiskClass::R4ExecOrPrivilege);
        let r = Op::egress_with_query(&TenantId::single(), &RunId("r".into()), "z", "GET", "github.com", "/octocat/hello.git/info/refs", "service=git-upload-pack");
        assert_eq!(r.risk, RiskClass::R1ReadScoped);
    }

    #[test]
    fn metadata_and_private_addresses_are_forbidden() {
        assert!(matches!(evaluate(&zone(), &op("GET", "169.254.169.254", "/latest")), Verdict::Forbidden(_)));
        assert!(matches!(evaluate(&zone(), &op("GET", "10.0.0.1", "/")), Verdict::Forbidden(_)));
        assert!(matches!(evaluate(&zone(), &op("GET", "localhost", "/")), Verdict::Forbidden(_)));
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

    #[test]
    fn hosts_are_judged_before_any_request() {
        let z = |extra: &str| Manifest::from_yaml(&format!("task: t\nagent: {{ name: a }}\nzone:\n  name: z\n  llm: {{}}\n  reach: [{{ host: api.example.com }}, {{ host: \"*.cdn.example\" }}]\n  forbid: [{{ host: mcp.example.com }}, {{ host: api.example.com, paths: [\"/private/**\"] }}]\n{extra}")).unwrap().zone;
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
}
