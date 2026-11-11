//! The capability algebra used by both encodings: a zone ceiling (one per chain link), a grant, and a
//! request as the node sees it. A cut-down version of wicket-core's ZoneSpec (manifest.rs) with paths
//! restricted to forms both encodings can express without regexes.
//!
//! biscuit-datablocks: copied from biscuit-fast; the only change is `deny_unknown_fields` on every
//! serialized type, because design B parses these from token facts.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub enum PathPat {
    /// Any path on the host (`/**`).
    Any,
    /// `/repos/acme/**`: a literal prefix ending in `/`.
    Prefix(String),
    /// `/tokio/*`: the prefix plus exactly one more segment.
    OneSegment(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Reach {
    /// Exact host, or `*.example.com`.
    pub host: String,
    pub methods: Vec<String>,
    pub path: PathPat,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Forbid {
    pub host: String,
    pub path_prefix: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SpawnLimits {
    pub images: Vec<String>,
    /// 1 = runc, 2 = gVisor.
    pub min_isolation: i64,
    pub mem_bytes: i64,
    pub cpus_milli: i64,
    pub pids: i64,
    pub timeout_s: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LlmBudget {
    pub max_requests: i64,
    pub max_output_tokens: i64,
}

/// One link's ceiling. Effective authority is the intersection over every link.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Ceiling {
    pub zone: String,
    /// This box and its descendants: `b0/b1` admits `b0/b1` and `b0/b1/...`.
    pub box_prefix: String,
    pub not_after: u64,
    pub ops: Vec<String>,
    pub reach: Vec<Reach>,
    pub forbid: Vec<Forbid>,
    /// Requests the dangerous-pattern list rates above this need `dangerous_ok` or a grant.
    pub max_risk: i64,
    pub dangerous_ok: Vec<Reach>,
    pub spawn: SpawnLimits,
    pub llm: LlmBudget,
    pub accept_from: Vec<String>,
    /// `host|header|secret` triples the egress proxy may inject.
    pub inject: Vec<String>,
    /// Ed25519 public keys (hex) whose grants this link's escalatable checks accept: the approval
    /// service, plus (for spawn links) the parent box's grantor key.
    pub grant_keys: Vec<String>,
    /// Benchmark variant only: compile path patterns to `.matches()` regexes instead of prefixes.
    #[serde(skip)]
    pub regex_paths: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub gid: String,
    pub box_id: String,
    pub epoch: i64,
    pub host: String,
    pub method: String,
    pub path: String,
    pub not_after: u64,
    pub approver: String,
    pub digest: String,
}

#[derive(Clone, Debug)]
pub enum Op {
    Http { host: String, method: String, path: String, risk: i64, inject: Option<String> },
    Spawn { image: String, isolation: i64, mem: i64, cpus: i64, pids: i64, secs: i64 },
    Llm { used_requests: i64, used_tokens: i64 },
    Msg { from: String },
}

impl Op {
    pub fn kind(&self) -> &'static str {
        match self {
            Op::Http { .. } => "http",
            Op::Spawn { .. } => "spawn",
            Op::Llm { .. } => "llm",
            Op::Msg { .. } => "msg",
        }
    }
}

/// What the node knows about one request: ambient facts, never taken from the box's own claims.
#[derive(Clone, Debug)]
pub struct Request {
    pub time: u64,
    pub tenant: String,
    pub node: String,
    pub box_id: String,
    pub epoch: i64,
    pub op: Op,
    /// From the node's ledger: (grant id, uses left).
    pub uses_left: Vec<(String, i64)>,
}

pub fn path_depth(p: &str) -> i64 {
    p.split('/').filter(|s| !s.is_empty()).count() as i64
}

pub fn host_matches(pat: &str, host: &str) -> bool {
    match pat.strip_prefix("*.") {
        Some(sfx) => host.len() > sfx.len() + 1 && host.ends_with(sfx) && host.as_bytes()[host.len() - sfx.len() - 1] == b'.',
        None => pat == host,
    }
}

pub fn path_matches(pat: &PathPat, path: &str) -> bool {
    match pat {
        PathPat::Any => true,
        PathPat::Prefix(p) => path.starts_with(p.as_str()),
        PathPat::OneSegment(p) => path.starts_with(p.as_str()) && path_depth(path) == path_depth(p) + 1,
    }
}

pub fn rfc3339(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

fn r(host: &str, methods: &[&str], path: PathPat) -> Reach {
    Reach { host: host.into(), methods: methods.iter().map(|s| s.to_string()).collect(), path }
}
fn pre(p: &str) -> PathPat {
    PathPat::Prefix(p.into())
}

pub const GH_INJECT: &str = "api.github.com|Authorization|gh-app-acme";

/// Box id of the box at spawn depth `d` (0 = the root box).
pub fn box_id(d: usize) -> String {
    let mut s = String::from("b0");
    for i in 1..=d {
        s.push_str(&format!("/b{i}"));
    }
    s
}

/// The ceiling at spawn depth `level` (0 = authority). Each level narrows the previous one.
pub fn level(t0: u64, level: usize, grant_keys: Vec<String>) -> Ceiling {
    let gib = 1i64 << 30;
    let mut c = Ceiling {
        zone: if level == 0 { "nightly-ci".into() } else { format!("nightly-ci.w{level}") },
        box_prefix: box_id(level),
        not_after: t0 + 8 * 3600,
        ops: ["http", "spawn", "llm", "msg"].map(String::from).to_vec(),
        reach: vec![
            r("api.github.com", &["GET", "HEAD", "POST", "PATCH"], pre("/repos/acme/")),
            r("*.githubusercontent.com", &["GET", "HEAD"], PathPat::Any),
            r("crates.io", &["GET", "HEAD"], pre("/api/v1/crates/")),
            r("static.crates.io", &["GET"], PathPat::Any),
            r("index.crates.io", &["GET"], PathPat::Any),
            r("docs.rs", &["GET"], PathPat::OneSegment("/tokio/".into())),
            r("pypi.org", &["GET"], pre("/simple/")),
            r("registry.npmjs.org", &["GET"], PathPat::Any),
        ],
        forbid: vec![
            Forbid { host: "*.internal".into(), path_prefix: None },
            Forbid { host: "api.github.com".into(), path_prefix: Some("/repos/acme/secrets-vault/".into()) },
        ],
        max_risk: 2,
        dangerous_ok: vec![r("api.github.com", &["GET", "HEAD", "POST", "PATCH", "PUT", "DELETE"], pre("/repos/acme/scratch/"))],
        spawn: SpawnLimits {
            images: ["img:agent", "img:rust", "img:py"].map(String::from).to_vec(),
            min_isolation: 2,
            mem_bytes: 8 * gib,
            cpus_milli: 4000,
            pids: 2048,
            timeout_s: 8 * 3600,
        },
        llm: LlmBudget { max_requests: 3000, max_output_tokens: 4_000_000 },
        accept_from: vec!["ops".into()],
        inject: vec![GH_INJECT.into()],
        grant_keys,
        regex_paths: false,
    };
    if level == 0 {
        return c;
    }
    // Spawn links never repeat the parent's forbids (they still apply, from the parent's block).
    c.forbid.clear();
    c.not_after = t0 + (7 - level as u64) * 3600;
    c.spawn.mem_bytes = (8 * gib) >> level;
    c.spawn.cpus_milli = 4000 >> level.min(3);
    c.spawn.pids = 2048 >> level;
    c.spawn.timeout_s = (7 - level as i64) * 3600;
    c.spawn.images = vec!["img:agent".into(), "img:rust".into()];
    c.llm.max_requests = 3000 / (level as i64 + 1);
    c.llm.max_output_tokens = 4_000_000 / (level as i64 + 1);
    c.reach.retain(|x| x.host != "registry.npmjs.org" && x.host != "pypi.org");
    if level >= 2 {
        c.reach[0].methods = vec!["GET".into(), "HEAD".into(), "POST".into()];
        c.reach.retain(|x| x.host != "docs.rs");
    }
    if level >= 3 {
        c.reach[0].path = pre("/repos/acme/api/");
        c.reach.retain(|x| x.host != "*.githubusercontent.com");
    }
    if level >= 4 {
        c.reach.retain(|x| x.host != "index.crates.io");
        c.dangerous_ok.clear();
    }
    if level >= 5 {
        c.reach[0].methods = vec!["GET".into(), "HEAD".into()];
        c.accept_from.clear();
    }
    c
}

pub fn scenarios(now: u64, leaf: usize) -> Vec<(&'static str, Request)> {
    let base = Request {
        time: now,
        tenant: "acme".into(),
        node: "node-lon-1".into(),
        box_id: box_id(leaf),
        epoch: 3,
        op: Op::Msg { from: "ops".into() },
        uses_left: vec![("g-7f3a".into(), 1)],
    };
    let http = |method: &str, path: &str, risk: i64| Op::Http {
        host: "api.github.com".into(),
        method: method.into(),
        path: path.into(),
        risk,
        inject: Some(GH_INJECT.into()),
    };
    vec![
        ("A allow (GET in reach)", Request { op: http("GET", "/repos/acme/api/pulls/7", 0), ..base.clone() }),
        ("B deny (outside reach)", Request { op: http("GET", "/repos/other/x/issues", 0), ..base.clone() }),
        ("C granted (PUT merge via approval)", Request { op: http("PUT", "/repos/acme/api/pulls/7/merge", 3), ..base.clone() }),
        (
            "D spawn (limits)",
            Request { op: Op::Spawn { image: "img:rust".into(), isolation: 2, mem: 256 << 20, cpus: 250, pids: 64, secs: 900 }, ..base },
        ),
    ]
}

pub fn leaf_grant(now: u64, leaf: usize) -> Grant {
    Grant {
        gid: "g-7f3a".into(),
        box_id: box_id(leaf),
        epoch: 3,
        host: "api.github.com".into(),
        method: "PUT".into(),
        path: "/repos/acme/api/pulls/7/merge".into(),
        not_after: now + 900,
        approver: "human:alex@acme".into(),
        digest: "5f1c0e7a9b3d42e8a1c6f0b7d9e2a4c3b8f1e6d0a7c9b2e4f3a1d8c6b0e9f7a2".into(),
    }
}
