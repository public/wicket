//! Shared test fixtures: keys, the depth-5 chain from experiments #59/biscuit-fast (with globs), the
//! example and subset-test zones, a small deterministic RNG and request generators.
#![allow(dead_code)]

use wicket_authz::*;
use wicket_core::{CompiledZone, Manifest, RiskClass, RunId, TenantId, Verdict, ZoneSpec};

#[path = "../../../wicket-core/tests/subset_cases.rs"]
pub mod subset_cases;

pub const T0: u64 = 1_800_000_000;
pub const TENANT: &str = "acme";
pub const GH_INJECT: &str = "api.github.com|Authorization|gh-app-acme";

/// splitmix64: deterministic, dependency-free.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn pick<'a, T>(&mut self, v: &'a [T]) -> &'a T {
        &v[self.below(v.len())]
    }
    pub fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

pub struct Keys {
    pub root: SigningKey,
    pub approver: SigningKey,
    /// One grantor key per box depth; a child's block trusts its parent's.
    pub grantor: Vec<SigningKey>,
}

impl Keys {
    pub fn new(max_depth: usize) -> Keys {
        Keys {
            root: SigningKey::generate(),
            approver: SigningKey::generate(),
            grantor: (0..=max_depth).map(|_| SigningKey::generate()).collect(),
        }
    }
}

pub fn never_revoked(_: &[u8]) -> bool {
    false
}

/// Box id at spawn depth `d`.
pub fn box_id(d: usize) -> String {
    let mut s = String::from("b0");
    for i in 1..=d {
        s.push_str(&format!("/b{i}"));
    }
    s
}

pub fn r(host: &str, methods: &[&str], paths: &[&str], dangerous: bool) -> Reach {
    Reach {
        host: host.into(),
        methods: methods.iter().map(|s| s.to_string()).collect(),
        paths: paths.iter().map(|s| s.to_string()).collect(),
        allow_dangerous: dangerous,
    }
}

/// The ceiling at spawn depth `level` (0 = authority), each level narrowing the previous one: the
/// layout of experiments #59 and biscuit-fast, with path globs instead of prefixes.
pub fn level(level: usize, grant_keys: Vec<PublicKey>) -> Ceiling {
    let gib = 1i64 << 30;
    let mut c = Ceiling {
        zone: if level == 0 { "nightly-ci".into() } else { format!("nightly-ci.w{level}") },
        box_prefix: box_id(level),
        not_after: T0 + 8 * 3600,
        ops: OpKind::ALL.to_vec(),
        reach: vec![
            r("api.github.com", &["GET", "HEAD", "POST", "PATCH"], &["/repos/acme/**"], false),
            r("*.githubusercontent.com", &["GET", "HEAD"], &["/**"], false),
            r("crates.io", &["GET", "HEAD"], &["/api/v1/crates/**"], false),
            r("static.crates.io", &["GET"], &["/**"], false),
            r("index.crates.io", &["GET"], &["/**"], false),
            r("docs.rs", &["GET"], &["/tokio/*"], false),
            r("pypi.org", &["GET"], &["/simple/**"], false),
            r("registry.npmjs.org", &["GET"], &["/**"], false),
            r("api.github.com", &["GET", "HEAD", "POST", "PATCH", "PUT", "DELETE"], &["/repos/acme/scratch/**"], true),
        ],
        forbid: vec![
            Forbid { host: "*.internal".into(), paths: vec!["/**".into()] },
            Forbid { host: "api.github.com".into(), paths: vec!["/repos/acme/secrets-vault/**".into()] },
        ],
        inject: vec![Inject { host: "api.github.com".into(), header: "Authorization".into(), secret: "gh-app-acme".into() }],
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
        grant_keys,
    };
    if level == 0 {
        return c;
    }
    // Spawn links don't repeat the parent's forbids: they still apply, from the parent's block.
    c.forbid.clear();
    c.not_after = T0 + (7 - level as u64) * 3600;
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
        c.reach[0].paths = vec!["/repos/acme/api/**".into()];
        c.reach.retain(|x| x.host != "*.githubusercontent.com");
    }
    if level >= 4 {
        c.reach.retain(|x| x.host != "index.crates.io" && !x.allow_dangerous);
    }
    if level >= 5 {
        c.reach[0].methods = vec!["GET".into(), "HEAD".into()];
        c.accept_from.clear();
    }
    c
}

/// Ceilings for depths 0..=depth: each trusts the approver, spawn links also the parent's grantor.
pub fn ceilings(depth: usize, keys: &Keys) -> Vec<Ceiling> {
    (0..=depth)
        .map(|l| {
            let mut gk = vec![keys.approver.public()];
            if l > 0 {
                gk.push(keys.grantor[l - 1].public());
            }
            level(l, gk)
        })
        .collect()
}

pub fn mint_chain(cs: &[Ceiling], keys: &Keys) -> Token {
    let mut t = mint(&keys.root, TENANT, &format!("trigger:{}", cs[0].zone), &cs[0]).expect("mint");
    for c in &cs[1..] {
        t = t.attenuate(c).expect("attenuate");
    }
    t
}

pub fn leaf_grant(leaf: usize) -> Grant {
    Grant {
        gid: "g-7f3a".into(),
        box_id: box_id(leaf),
        epoch: 3,
        host: "api.github.com".into(),
        method: "PUT".into(),
        path: "/repos/acme/api/pulls/7/merge".into(),
        not_after: T0 + 600 + 900,
        approver: "human:alex@acme".into(),
        digest: vec![0x5f, 0x1c, 0x0e, 0x7a],
    }
}

pub fn http(method: &str, host: &str, path: &str, risk: RiskClass) -> Action {
    Action::Http { host: host.into(), method: method.into(), path: path.into(), risk, inject: Some(GH_INJECT.into()) }
}

pub fn base_request(leaf: usize) -> Request {
    Request {
        time: T0 + 600,
        tenant: TENANT.into(),
        box_id: box_id(leaf),
        epoch: 3,
        action: Action::Msg { from: "ops".into() },
        uses_left: vec![("g-7f3a".into(), 1)],
    }
}

/// The four scenarios of #59: A allowed by reach, B outside reach, C allowed by the leaf grant, D a
/// spawn within limits.
pub fn scenarios(leaf: usize) -> Vec<(&'static str, Request)> {
    let base = base_request(leaf);
    vec![
        ("A", Request { action: http("GET", "api.github.com", "/repos/acme/api/pulls/7", RiskClass::R1ReadScoped), ..base.clone() }),
        ("B", Request { action: http("GET", "api.github.com", "/repos/other/x/issues", RiskClass::R1ReadScoped), ..base.clone() }),
        (
            "C",
            Request {
                action: http("PUT", "api.github.com", "/repos/acme/api/pulls/7/merge", RiskClass::R4ExecOrPrivilege),
                ..base.clone()
            },
        ),
        (
            "D",
            Request {
                action: Action::Spawn {
                    image: "img:rust".into(),
                    isolation: 2,
                    mem_bytes: 256 << 20,
                    cpus_milli: 250,
                    pids: 64,
                    timeout_s: 900,
                },
                ..base
            },
        ),
    ]
}

pub fn load_ok(t: &Token, keys: &Keys) -> Loaded {
    load(&t.to_bytes().unwrap(), &keys.root.public(), &never_revoked).expect("load")
}

pub fn load_err(t: &Token, keys: &Keys) -> String {
    match load(&t.to_bytes().unwrap(), &keys.root.public(), &never_revoked) {
        Ok(_) => panic!("loaded a token that should be refused"),
        Err(e) => e.to_string(),
    }
}

// --- zones -------------------------------------------------------------------------------------

pub fn example_zones() -> Vec<ZoneSpec> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../examples");
    let mut files: Vec<String> = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "yaml") {
            files.push(p.display().to_string());
        } else if p.join("manifest.yaml").exists() {
            files.push(p.join("manifest.yaml").display().to_string());
        }
    }
    files.sort();
    files.iter().map(|f| Manifest::from_yaml(&std::fs::read_to_string(f).unwrap()).unwrap_or_else(|e| panic!("{f}: {e}")).zone).collect()
}

/// The example manifests' zones, then the subset tests' 7 parents and 32 children.
pub fn all_zones() -> Vec<ZoneSpec> {
    let mut v = example_zones();
    v.extend(subset_cases::parents().into_iter().map(|p| p.zone));
    v.extend(subset_cases::children().into_iter().map(|c| c.zone));
    v
}

/// Paths a glob matches, and near misses (as in wicket-core's `compiled_zones_decide_as_before`).
pub fn paths_for(glob: &str) -> Vec<String> {
    let fill = |g: &str, one: &str, many: &str| g.replace("**", many).replace('*', one).replace(['{', '}'], "").replace(',', "");
    let mut v = vec![fill(glob, "x", "a/b"), fill(glob, "", "z"), fill(glob, "abc123", "abc123/worker")];
    if let Some((parent, _)) = glob.rsplit_once('/') {
        v.push(format!("{}/", fill(parent, "x", "a")));
        v.push(fill(parent, "x", "a"));
        v.push(format!("{}/other", fill(parent, "x", "a")));
    }
    v.into_iter().map(|p| if p.starts_with('/') { p } else { format!("/{p}") }).collect()
}

/// Hosts and paths to try against a set of zones.
pub fn probes(zones: &[&ZoneSpec]) -> (Vec<String>, Vec<String>) {
    let mut hosts: Vec<String> = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    for z in zones {
        hosts.extend(z.reach.iter().map(|x| &x.host).chain(z.forbid.iter().map(|f| &f.host)).map(|h| h.replace("*.", "a.")));
        paths.extend(
            z.reach.iter().flat_map(|x| x.paths.iter()).chain(z.forbid.iter().flat_map(|f| f.paths.iter())).flat_map(|g| paths_for(g)),
        );
        // Forbids ignore ASCII case (#115): their paths spelled in upper case too.
        paths.extend(z.forbid.iter().flat_map(|f| f.paths.iter()).flat_map(|g| paths_for(g)).map(|p| p.to_ascii_uppercase()));
    }
    hosts.extend(["github.com", "api.github.com", "example.com", "169.254.169.254", "localhost", "a.b.example.com"].map(String::from));
    paths.extend(
        [
            "/",
            "/x",
            "/octocat/Hello-World.git/git-receive-pack",
            "/caf\u{e9}/x",
            "/CAF\u{e9}/X",
            "/repos/acme/scratch/issues",
            "/REPOS/ACME/SCRATCH/ISSUES",
            "/x/admin",
            "/x/a/b",
            "/x/admin/users/delete",
            "/x/a0b",
        ]
        .map(String::from),
    );
    hosts.sort();
    hosts.dedup();
    paths.sort();
    paths.dedup();
    (hosts, paths)
}

pub const METHODS: [&str; 6] = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"];

pub fn op(zone: &str, m: &str, h: &str, p: &str) -> wicket_core::Op {
    wicket_core::Op::egress(&TenantId(TENANT.into()), &RunId("r".into()), zone, m, h, p)
}

/// wicket-core's verdict as a decision kind.
pub fn kind_of_verdict(v: &Verdict) -> u8 {
    match v {
        Verdict::AllowByReach(_) => 0,
        Verdict::Forbidden(_) => 1,
        Verdict::NeedsGrant(_) => 2,
    }
}

pub fn kind_of(d: &Decision) -> u8 {
    match d {
        Decision::Allow => 0,
        Decision::Forbidden(_) => 1,
        Decision::NeedsGrant(_) => 2,
    }
}

/// The decision a chain of zones makes by intersection: allowed iff every zone allows, forbidden if
/// any forbids, else a grant is needed.
pub fn intersect(zones: &[CompiledZone], o: &wicket_core::Op) -> u8 {
    let ks: Vec<u8> = zones.iter().map(|z| kind_of_verdict(&z.evaluate(o))).collect();
    if ks.contains(&1) {
        1
    } else if ks.iter().all(|&k| k == 0) {
        0
    } else {
        2
    }
}

pub fn http_request(box_id: &str, o: &wicket_core::Op) -> Request {
    Request { time: T0, tenant: TENANT.into(), box_id: box_id.into(), epoch: 1, action: Action::from_op(o, None), uses_left: vec![] }
}
