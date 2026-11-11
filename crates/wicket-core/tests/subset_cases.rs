//! The 28 parent/child zones from experiment #58 (experiments/symcc-zones), with the answers SymCC's
//! segment model proved. `subset::check` must agree on every one: it missed the forbid cases (22 and
//! 27) and wrongly refused one session's worker channel under any session's (19) before #73.

use std::time::Duration;
use wicket_core::{Manifest, ZoneSpec};

struct Parent {
    key: &'static str,
    zone: ZoneSpec,
    images: Vec<String>,
    llm_remaining: Option<(u64, u64)>,
    time_remaining: Duration,
    child_slots: u32,
}

struct Child {
    parent: &'static str,
    name: String,
    zone: ZoneSpec,
    image: String,
    max_children: u32,
    /// Expected: within the parent (true) or wider (false), and how.
    within: bool,
    note: &'static str,
}

fn zone(name: &str, body: &str) -> ZoneSpec {
    let llm = if body.contains("  llm:") { "" } else { "  llm: {}\n" };
    Manifest::from_yaml(&format!("task: t\nagent: {{ name: a }}\nzone:\n  name: {name}\n{llm}{body}"))
        .unwrap_or_else(|e| panic!("{name}: {e}"))
        .zone
}

fn example(path: &str) -> ZoneSpec {
    let p = format!("{}/../../examples/{path}", env!("CARGO_MANIFEST_DIR"));
    Manifest::from_yaml(&std::fs::read_to_string(&p).unwrap()).unwrap().zone
}

fn parents() -> Vec<Parent> {
    vec![
        Parent {
            key: "self-hosting",
            zone: example("self-hosting/manifest.yaml"),
            images: vec!["wicket-dev:0.0.1".into(), "rust:1.99".into()],
            llm_remaining: Some((200, 300_000)),
            time_remaining: Duration::from_secs(7200),
            child_slots: 4,
        },
        Parent {
            key: "research",
            zone: example("hello-github.yaml"),
            images: vec!["wicket-dev:0.0.1".into()],
            llm_remaining: Some((40, 40_000)),
            time_remaining: Duration::from_secs(600),
            child_slots: 2,
        },
        Parent {
            key: "remote-control",
            zone: example("remote-control/manifest.yaml"),
            images: vec!["wicket-dev:0.0.1".into()],
            llm_remaining: Some((300, 400_000)),
            time_remaining: Duration::from_secs(3600),
            child_slots: 2,
        },
        Parent {
            key: "subset-rs",
            zone: zone("z", "  reach:\n    - { host: api.github.com, paths: [\"/repos/acme/**\"] }\n    - { host: \"*.example.com\", methods: [GET, HEAD, POST] }\n    - { host: docs.rs, paths: [\"/tokio/*\"] }\n  inject: [{ host: api.github.com, header: Authorization, format: \"Bearer {secret}\", secret: gh }]\n  limits: { memory: 2g, cpus: 2, timeout: 1h }\n  accept_from: [ops]\n"),
            images: vec!["img:a".into(), "img:b".into()],
            llm_remaining: Some((100, 50_000)),
            time_remaining: Duration::from_secs(1800),
            child_slots: 3,
        },
        Parent {
            key: "subset-rs-hide",
            zone: zone("z", "  unlisted_hosts: hide\n"),
            images: vec!["img:a".into(), "img:b".into()],
            llm_remaining: Some((100, 50_000)),
            time_remaining: Duration::from_secs(1800),
            child_slots: 3,
        },
        Parent {
            key: "forbid-parent",
            zone: zone("z", "  reach:\n    - { host: api.example.com, methods: [GET, POST], paths: [\"/**\"] }\n  forbid:\n    - { host: api.example.com, paths: [\"/private/**\"] }\n    - { host: mcp.example.com }\n  limits: { memory: 2g, cpus: 1, timeout: 1h }\n"),
            images: vec!["img:a".into()],
            llm_remaining: Some((100, 50_000)),
            time_remaining: Duration::from_secs(1800),
            child_slots: 3,
        },
    ]
}

const SH_LLM: &str = "  llm: { secret: claude-oauth, max_requests: 50, max_output_tokens: 100000 }\n";
const SH_LIMITS: &str = "  limits: { memory: 1g, cpus: 1, timeout: 30m, pids: 512 }\n";
const SH_GIT: &str =
    "    - { host: github.com, methods: [GET, POST], paths: [\"/public/wicket.git/info/refs\", \"/public/wicket.git/git-upload-pack\"] }\n";
const SH_INJ: &str = "  inject:\n    - { host: api.github.com, header: Authorization, format: \"Bearer {secret}\", secret: github-wicket, optional: true }\n";

fn sh(name: &str, reach_extra: &str, rest: &str, within: bool, note: &'static str) -> Child {
    let body = format!(
        "  isolation: gvisor\n  reach:\n    - {{ host: index.crates.io }}\n    - {{ host: static.crates.io }}\n{reach_extra}{rest}"
    );
    let body = if body.contains("  llm:") { body } else { format!("{body}{SH_LLM}") };
    let body = if body.contains("  limits:") { body } else { format!("{body}{SH_LIMITS}") };
    Child {
        parent: "self-hosting",
        name: name.into(),
        zone: zone(name, &body),
        image: "wicket-dev:0.0.1".into(),
        max_children: 0,
        within,
        note,
    }
}

fn children() -> Vec<Child> {
    let mut v = vec![
        sh("sh-crates-only", "", "", true, "only the crates hosts"),
        sh("sh-issues-reader", &format!("{SH_GIT}    - {{ host: api.github.com, paths: [\"/repos/public/wicket/issues\", \"/repos/public/wicket/issues/**\"] }}\n"), SH_INJ, true, "issues subtree, same git fetch, same injection"),
        sh("sh-brace-star", "    - { host: api.github.com, paths: [\"/repos/public/wicket/{issues,pulls}/*\"] }\n", "", true, "brace alternation and one-segment *"),
        {
            let mut c = Child { parent: "self-hosting", name: "sh-copy".into(), zone: example("self-hosting/manifest.yaml"), image: "wicket-dev:0.0.1".into(), max_children: 2, within: true, note: "the parent's own zone (timeout cut to time left)" };
            c.zone.name = "sh-copy".into();
            c.zone.limits.timeout = "2h".into();
            if let Some(l) = c.zone.llm.as_mut() {
                l.max_requests = 200;
                l.max_output_tokens = 300_000;
            }
            c
        },
        sh("sh-extra-host", "    - { host: example.com }\n", "", false, "extra host"),
        sh("sh-extra-method", "    - { host: api.github.com, methods: [GET, HEAD, POST], paths: [\"/repos/public/wicket/issues\"] }\n", "", false, "extra method (POST)"),
        sh("sh-wider-path", "    - { host: api.github.com, paths: [\"/repos/public/**\"] }\n", "", false, "wider path (/repos/public/**)"),
        sh("sh-wildcard-host", "    - { host: \"*.github.com\" }\n", "", false, "wildcard host *.github.com"),
        sh("sh-push", "    - { host: github.com, methods: [POST], paths: [\"/public/wicket.git/git-receive-pack\"] }\n", "", false, "push path"),
        sh("sh-dangerous", "    - { host: api.github.com, paths: [\"/repos/public/wicket/**\"], allow_dangerous: true }\n", "", false, "allow_dangerous on a reach rule"),
        sh("sh-memory", "", "  limits: { memory: 4g, cpus: 1, timeout: 30m, pids: 512 }\n", false, "memory 4g > 3g"),
        sh("sh-inject-secret", "    - { host: api.github.com, paths: [\"/repos/public/wicket\"] }\n", "  inject:\n    - { host: api.github.com, header: Authorization, format: \"Bearer {secret}\", secret: github-admin }\n", false, "a different credential"),
        {
            let mut c = sh("sh-runc", "", "", false, "isolation runc");
            c.zone.isolation = wicket_core::Isolation::Runc;
            c
        },
        // research (examples/hello-github.yaml)
        rs("rs-commits", "    - { host: api.github.com, methods: [GET], paths: [\"/repos/octocat/Hello-World/commits/**\"] }\n", true, "GET-only commits subtree"),
        rs("rs-refs", "    - { host: github.com, methods: [GET], paths: [\"/octocat/Hello-World.git/info/refs\"] }\n", true, "one git path, GET only"),
        rs("rs-owner", "    - { host: api.github.com, paths: [\"/repos/octocat/**\"] }\n", false, "wider path (/repos/octocat/**)"),
        rs("rs-put", "    - { host: api.github.com, methods: [PUT], paths: [\"/repos/octocat/Hello-World/contents/**\"] }\n", false, "extra method (PUT)"),
        rs("rs-git-glob", "    - { host: github.com, methods: [GET], paths: [\"/octocat/Hello-World.git/**\"] }\n", false, "glob over a list of exact paths"),
        // remote-control (forbids; one-segment * next to **)
        rc("rc-one-session", "    - { host: api.anthropic.com, methods: [GET, PUT, POST], paths: [\"/v1/code/sessions/abc123/worker\", \"/v1/code/sessions/abc123/worker/**\"] }\n", true, true, "one session's worker channel"),
        rc("rc-messages", "    - { host: api.anthropic.com, methods: [POST], paths: [\"/v1/messages\"] }\n", true, true, "model calls only"),
        {
            let mut c = Child { parent: "remote-control", name: "rc-copy".into(), zone: example("remote-control/manifest.yaml"), image: "wicket-dev:0.0.1".into(), max_children: 0, within: true, note: "the parent's own zone" };
            c.zone.name = "rc-copy".into();
            c.zone.limits.timeout = "1h".into();
            if let Some(l) = c.zone.llm.as_mut() {
                l.max_requests = 300;
                l.max_output_tokens = 400_000;
            }
            c
        },
        {
            let mut c = Child { parent: "remote-control", name: "rc-missing-forbid".into(), zone: example("remote-control/manifest.yaml"), image: "wicket-dev:0.0.1".into(), max_children: 0, within: false, note: "same reach, forbids dropped" };
            c.zone.name = "rc-missing-forbid".into();
            c.zone.forbid.clear();
            c.zone.limits.timeout = "1h".into();
            if let Some(l) = c.zone.llm.as_mut() {
                l.max_requests = 300;
                l.max_output_tokens = 400_000;
            }
            c
        },
        rc("rc-delete", "    - { host: api.anthropic.com, methods: [DELETE], paths: [\"/v1/code/sessions/*/worker\"] }\n", true, false, "extra method (DELETE) on the worker path"),
        // subset.rs's own tests
        Child {
            parent: "subset-rs",
            name: "t-narrower".into(),
            zone: zone("t-narrower", "  reach:\n    - { host: api.github.com, paths: [\"/repos/acme/api/**\", \"/repos/acme/api\"] }\n    - { host: www.example.com }\n    - { host: \"*.cdn.example.com\" }\n    - { host: docs.rs, paths: [\"/tokio/latest\"] }\n  inject: [{ host: api.github.com, header: Authorization, format: \"Bearer {secret}\", secret: gh }]\n  llm: { max_requests: 40, max_output_tokens: 20000 }\n  limits: { memory: 1500m, cpus: 1, timeout: 20m }\n  accept_from: [z, ops]\n"),
            image: "img:b".into(),
            max_children: 0,
            within: true,
            note: "subset.rs a_narrower_zone_passes",
        },
        Child {
            parent: "subset-rs",
            name: "t-every-widening".into(),
            zone: zone("t-every-widening", "  isolation: runc\n  reach:\n    - { host: api.github.com, methods: [PUT], paths: [\"/repos/acme/**\"] }\n    - { host: api.github.com, paths: [\"/repos/other/**\"] }\n    - { host: \"*.com\" }\n    - { host: docs.rs, paths: [\"/tokio/**\"] }\n    - { host: example.com }\n  inject: [{ host: api.github.com, header: Authorization, format: \"Bearer {secret}\", secret: admin-token }]\n  llm: { max_requests: 500, secret: other }\n  limits: { memory: 4g, cpus: 4, timeout: 2h }\n  images: [img:root]\n  accept_from: [anyone]\n"),
            image: "img:root".into(),
            max_children: 5,
            within: false,
            note: "subset.rs every_widening_is_named (16 widenings)",
        },
        Child { parent: "subset-rs-hide", name: "t-hidden".into(), zone: zone("t-hidden", ""), image: "img:b".into(), max_children: 0, within: false, note: "subset.rs hidden_hosts_stay_hidden" },
        Child {
            parent: "forbid-parent",
            name: "f-no-forbid".into(),
            zone: zone("f-no-forbid", "  reach:\n    - { host: api.example.com, methods: [GET, POST], paths: [\"/**\"] }\n  limits: { memory: 1g, cpus: 1, timeout: 20m }\n  llm: { max_requests: 40, max_output_tokens: 20000 }\n"),
            image: "img:a".into(),
            max_children: 0,
            within: false,
            note: "same reach, the parent's forbids missing",
        },
        Child {
            parent: "forbid-parent",
            name: "f-inherited".into(),
            zone: zone("f-inherited", "  reach:\n    - { host: api.example.com, methods: [GET], paths: [\"/**\"] }\n  forbid:\n    - { host: api.example.com, paths: [\"/private/**\"] }\n    - { host: mcp.example.com }\n  limits: { memory: 1g, cpus: 1, timeout: 20m }\n  llm: { max_requests: 40, max_output_tokens: 20000 }\n"),
            image: "img:a".into(),
            max_children: 0,
            within: true,
            note: "GET only, forbids inherited as spawn.rs does",
        },
    ];
    v.sort_by_key(|c| order(c.parent));
    v
}

fn order(p: &str) -> usize {
    ["self-hosting", "research", "remote-control", "subset-rs", "subset-rs-hide", "forbid-parent"].iter().position(|x| *x == p).unwrap()
}

fn rs(name: &str, reach: &str, within: bool, note: &'static str) -> Child {
    let body = format!("  isolation: gvisor\n  reach:\n{reach}  llm: {{ secret: claude-oauth, max_requests: 20, max_output_tokens: 20000 }}\n  limits: {{ memory: 1g, cpus: 1, timeout: 10m }}\n");
    Child {
        parent: "research",
        name: name.into(),
        zone: zone(name, &body),
        image: "wicket-dev:0.0.1".into(),
        max_children: 0,
        within,
        note,
    }
}

fn rc(name: &str, reach: &str, with_forbids: bool, within: bool, note: &'static str) -> Child {
    let forbid = if with_forbids {
        "  forbid:\n    - { host: mcp-proxy.anthropic.com }\n    - { host: api.anthropic.com, paths: [\"/v1/mcp_servers\", \"/v1/mcp_servers/**\", \"/mcp-registry/**\"] }\n"
    } else {
        ""
    };
    let body = format!("  isolation: gvisor\n  reach:\n{reach}{forbid}  llm: {{ secret: claude-oauth, max_requests: 100, max_output_tokens: 100000 }}\n  limits: {{ memory: 1g, cpus: 1, timeout: 30m }}\n");
    Child {
        parent: "remote-control",
        name: name.into(),
        zone: zone(name, &body),
        image: "wicket-dev:0.0.1".into(),
        max_children: 0,
        within,
        note,
    }
}

#[test]
fn subset_check_agrees_with_symcc_on_every_case() {
    use wicket_core::subset;
    let parents = parents();
    let mut wrong = vec![];
    for (n, c) in children().iter().enumerate() {
        let p = parents.iter().find(|p| p.key == c.parent).unwrap();
        let bounds = subset::Bounds {
            zone: &p.zone,
            images: p.images.clone(),
            llm_remaining: p.llm_remaining,
            time_remaining: p.time_remaining,
            child_slots: p.child_slots,
        };
        let ask = subset::Ask { zone: &c.zone, image: &c.image, max_children: c.max_children };
        let got = subset::check(&ask, &bounds);
        if got.is_ok() != c.within {
            wrong.push(format!(
                "#{} {} under {} ({}): expected {}, got {got:?}",
                n + 1,
                c.name,
                c.parent,
                c.note,
                if c.within { "within" } else { "wider" }
            ));
        }
    }
    assert_eq!(children().len(), 28);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
