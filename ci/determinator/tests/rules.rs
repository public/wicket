//! The rules' own tests (#218), on the workspace as it is: synthetic changes and what they select,
//! the filterset nextest would run for them, every path the rules name, and every file a crate
//! reads from outside its own directory.

use camino::Utf8PathBuf;
use guppy::graph::cargo::BuildPlatform;
use guppy::graph::PackageGraph;
use nextest_filtering::{BinaryQuery, EvalContext, Filterset, FiltersetKind, KnownGroups, ParseContext};
use nextest_metadata::{RustBinaryId, RustTestBinaryKind};
use std::collections::BTreeSet;
use std::sync::OnceLock;
use wicket_affected::*;

fn root() -> Utf8PathBuf {
    Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize_utf8().unwrap()
}

fn head() -> &'static PackageGraph {
    static G: OnceLock<PackageGraph> = OnceLock::new();
    G.get_or_init(|| graph(&root()).expect("the workspace's package graph"))
}

fn select(files: &[&str]) -> Selection {
    let files: Vec<Utf8PathBuf> = files.iter().map(Utf8PathBuf::from).collect();
    let suites = Suites::parse(SUITES).unwrap();
    Selection::compute(head(), head(), &files, &rules().unwrap(), &suites).unwrap()
}

fn set(xs: &[&str]) -> BTreeSet<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

/// Every fuzz target's suite.
fn every_fuzz() -> Vec<String> {
    Suites::parse(SUITES).unwrap().fuzz_targets.iter().map(|t| format!("fuzz-{t}")).collect()
}

/// The crates nextest's filterset selects, evaluated by nextest's own filterset code on the graph.
fn nextest_selects(filter: &str) -> BTreeSet<String> {
    let cx = ParseContext::new(head());
    let parse = |s: &str| Filterset::parse(s.into(), &cx, FiltersetKind::Test, &KnownGroups::Unavailable).unwrap();
    let f = parse(filter);
    let all = parse("all()");
    let ecx = EvalContext { default_filter: &all.compiled };
    head()
        .workspace()
        .iter()
        .filter(|p| {
            let id = RustBinaryId::new(p.name());
            let q = BinaryQuery {
                package_id: p.id(),
                binary_id: &id,
                binary_name: p.name(),
                kind: &RustTestBinaryKind::LIB,
                platform: BuildPlatform::Target,
            };
            f.matches_binary(&q, &ecx).expect("a package filterset decides per binary")
        })
        .map(|p| p.name().to_string())
        .collect()
}

#[track_caller]
fn check(files: &[&str], crates: &[&str], suites: &[&str]) {
    let s = select(files);
    assert!(!s.everything, "{files:?}: everything ({:?})", s.why);
    assert_eq!(s.affected, set(crates), "{files:?}: crates ({:?})", s.why);
    assert_eq!(s.suites, set(suites), "{files:?}: suites");
    // nextest, given the filterset, runs the tests of exactly the affected crates.
    if !crates.is_empty() {
        assert_eq!(nextest_selects(&s.filter()), s.affected, "{files:?}: filter {}", s.filter());
    } else {
        assert_eq!(s.filter(), "", "{files:?}");
    }
}

#[track_caller]
fn everything(files: &[&str]) {
    let s = select(files);
    assert!(s.everything, "{files:?} should select everything: {:?}", s.why);
    assert_eq!(s.filter(), "all()");
    assert_eq!(s.cargo_args(&members(head())), "--workspace");
}

// wicket-cli's suites: every end-to-end suite but policy, kani and lean.
const CLI: &[&str] =
    &["tla", "smoke", "hibernate", "restore", "acceptance", "daemon-uids", "install-test", "node-e2e", "acceptance-nodes", "update"];

fn with(a: &[&'static str], b: &[&'static str]) -> Vec<&'static str> {
    a.iter().chain(b).copied().collect()
}

#[test]
fn documentation_selects_nothing() {
    check(&["docs/reference/agents.md", "README.md", "experiments/x/RESULTS.md", "changes/1.md"], &[], &[]);
    check(&["fuzz/README.md", "refs/x.txt", "LICENSE", "deny.toml"], &[], &[]);
}

#[test]
fn the_cli_reference_is_checked_by_a_cli_test() {
    check(&["docs/reference/cli.md"], &["wicket-cli"], CLI);
}

#[test]
fn a_crate_selects_its_reverse_dependencies() {
    let fwd = ["wicket-fwd", "wicket-proxy", "wicket-chan", "wicket-home", "wicket-node", "wicket-control", "wicket-cli", "wicket-sim"];
    let fuzz = ["fuzz-egress", "fuzz-gateway", "fuzz-chan"];
    check(&["crates/wicket-fwd/src/copy.rs"], &fwd, &with(CLI, &fuzz));
    let s = select(&["crates/wicket-fwd/src/copy.rs"]);
    assert_eq!(s.filter(), "rdeps(=wicket-fwd)");
    assert_eq!(s.cargo_args(&members(head())), "-p wicket-chan -p wicket-cli -p wicket-control -p wicket-fwd -p wicket-home -p wicket-node -p wicket-proxy -p wicket-sim");
    check(&["crates/wicket-sandbox/tests/x.rs"], &["wicket-sandbox", "wicket-home", "wicket-node", "wicket-control", "wicket-cli"], CLI);
    // A deleted file is still its crate's.
    check(&["crates/wicket-sandbox/src/gone.rs"], &["wicket-sandbox", "wicket-home", "wicket-node", "wicket-control", "wicket-cli"], CLI);
    // A crate's own notes stay its crate's.
    check(&["crates/wicket-fwd/NOTES.md"], &fwd, &with(CLI, &fuzz));
}

#[test]
fn wicket_core_is_nearly_everything_but_not_everything() {
    let s = select(&["crates/wicket-core/src/op.rs"]);
    assert!(!s.everything);
    assert_eq!(s.roots, set(&["wicket-core"]));
    assert_eq!(s.filter(), "rdeps(=wicket-core)");
    for c in ["wicket-auth", "wicket-identity", "wicket-fwd", "wicket-placement"] {
        assert!(!s.affected.contains(c), "{c}");
    }
    assert!(s.affected.len() >= 10);
    assert_eq!(nextest_selects(&s.filter()), s.affected);
    // Every suite: kani and lean through wicket-core and wicket-authz, every fuzz target.
    let all: BTreeSet<String> = Suites::parse(SUITES).unwrap().names().map(String::from).collect();
    assert_eq!(s.suites, all);
}

#[test]
fn policy_code() {
    check(
        &["crates/wicket-policy/tests/cedar.rs"],
        &["wicket-policy", "wicket-policy-diff", "wicket-control", "wicket-cli"],
        &with(CLI, &["policy", "fuzz-manifest"]),
    );
}

#[test]
fn the_simulation_follows_the_run_loops() {
    let f = "crates/wicket-cli/src/reconcile.rs";
    check(&[f], &["wicket-cli", "wicket-sim"], CLI);
    assert_eq!(select(&[f]).filter(), "rdeps(=wicket-cli) | rdeps(=wicket-sim)");
    for f in ["crates/wicket-control/src/hibernate.rs", "crates/wicket-control/src/noderun.rs"] {
        check(&[f], &["wicket-control", "wicket-cli", "wicket-sim"], CLI);
        assert_eq!(select(&[f]).filter(), "rdeps(=wicket-control) | rdeps(=wicket-sim)");
    }
    for f in ["crates/wicket-node/src/nodesrv.rs", "crates/wicket-node/src/nodegw.rs"] {
        check(&[f], &["wicket-node", "wicket-control", "wicket-cli", "wicket-sim"], CLI);
        assert_eq!(select(&[f]).filter(), "rdeps(=wicket-node) | rdeps(=wicket-sim)");
    }
    check(&["crates/wicket-cli/src/cmd/run.rs"], &["wicket-cli"], CLI);
}

/// The modules that left wicket-cli for wicket-home (#219) still select wicket-cli and its suites.
#[test]
fn wicket_home_selects_wicket_cli() {
    check(&["crates/wicket-home/src/statestore.rs"], &["wicket-home", "wicket-node", "wicket-control", "wicket-cli"], CLI);
    let s = select(&["crates/wicket-home/src/nodeauth.rs"]);
    assert_eq!(s.filter(), "rdeps(=wicket-home)");
    check(&["deploy/install.sh"], &["wicket-home", "wicket-node", "wicket-control", "wicket-cli"], CLI);
    let s = select(&["examples/program-repo-stats.pinned.yaml"]);
    assert!(set(&["wicket-home", "wicket-cli"]).is_subset(&s.affected));
}

/// The node, which left wicket-cli for wicket-node (#219), still selects wicket-cli and its suites,
/// and only a node module the simulation doesn't follow leaves wicket-sim out.
#[test]
fn wicket_node_selects_wicket_cli() {
    check(&["crates/wicket-node/src/nodesrv/volumes.rs"], &["wicket-node", "wicket-control", "wicket-cli"], CLI);
    assert_eq!(select(&["crates/wicket-node/src/status.rs"]).filter(), "rdeps(=wicket-node)");
}

/// The control host's core, which left wicket-cli for wicket-control (#219), still selects wicket-cli
/// and its suites; a change to the CLI's own modules (the console, the daemon, the commands) no
/// longer selects wicket-control.
#[test]
fn wicket_control_selects_wicket_cli() {
    check(&["crates/wicket-control/src/run.rs"], &["wicket-control", "wicket-cli"], CLI);
    assert_eq!(select(&["crates/wicket-control/src/grant.rs"]).filter(), "rdeps(=wicket-control)");
    check(&["crates/wicket-cli/src/serve/web.rs"], &["wicket-cli"], CLI);
    let s = select(&["images/claude-code/Dockerfile"]);
    assert!(set(&["wicket-control", "wicket-cli"]).is_subset(&s.affected) && s.suites.contains("smoke"));
}

#[test]
fn the_toolchain_cargo_and_ci_select_everything() {
    for f in [
        "rust-toolchain.toml",
        ".cargo/config.toml",
        ".config/nextest.toml",
        ".github/workflows/ci.yml",
        "Cargo.toml",
        "ci/determinator/rules.toml",
        "ci/determinator/suites.toml",
        "ci/gates.sh",
        "third_party/biscuit-auth/src/lib.rs",
    ] {
        everything(&[f]);
    }
    everything(&["somewhere/new.txt"]);
    everything(&[]);
}

#[test]
fn the_lockfile_selects_what_its_change_rebuilds() {
    // Compared with itself, the lockfile changes no crate's build; wicket-policy's test reads it.
    check(&["Cargo.lock"], &["wicket-policy", "wicket-policy-diff", "wicket-control", "wicket-cli"], &with(CLI, &["policy", "fuzz-manifest"]));
    // A crate's manifest is its crate's (and its simulated build's).
    check(&["crates/wicket-placement/Cargo.toml"], &["wicket-placement", "wicket-control", "wicket-cli", "wicket-sim"], &with(CLI, &[]));
}

#[test]
fn fuzz_targets() {
    check(&["fuzz/src/store.rs"], &[], &["fuzz-store"]);
    check(&["fuzz/regressions/egress/x", "fuzz/corpus/git/y"], &[], &["fuzz-egress", "fuzz-git"]);
    check(&["fuzz/fuzz_targets/chan.rs"], &[], &["fuzz-chan"]);
    check(&["fuzz/src/node_chan.rs"], &[], &["fuzz-chan"]);
    let every = every_fuzz();
    let every: Vec<&str> = every.iter().map(String::as_str).collect();
    for f in ["fuzz/src/lib.rs", "fuzz/Cargo.toml", "fuzz/Cargo.lock", "ci/fuzz.sh", "fuzz/tests/corpus.rs"] {
        check(&[f], &[], &every);
    }
    // The code a target fuzzes, through its crate.
    let s = select(&["crates/wicket-store/src/cas.rs"]);
    for t in ["fuzz-store", "fuzz-egress", "fuzz-gateway", "fuzz-chan"] {
        assert!(s.suites.contains(t), "{t}");
    }
    assert!(!s.suites.contains("fuzz-token"));
}

#[test]
fn inputs_from_outside_the_crates() {
    let s = select(&["examples/demo.yaml"]);
    assert!(set(&["wicket-core", "wicket-authz", "wicket-feed", "wicket-policy", "wicket-cli"]).is_subset(&s.affected));
    assert!(s.suites.contains("lean") && s.suites.contains("policy"));
    let s = select(&["images/claude-code/wicket-entry"]);
    assert!(set(&["wicket-cli", "wicket-fwd"]).is_subset(&s.affected) && s.suites.contains("smoke"));
    check(&["web/session/src/main.ts"], &["wicket-cli"], CLI);
    let s = select(&["crates/wicket-authz/tests/common/mod.rs"]);
    assert!(s.affected.contains("wicket-feed") && s.suites.contains("lean"));
    let s = select(&["crates/wicket-core/tests/integration/subset_cases.rs"]);
    assert!(s.roots.contains("wicket-core") && s.affected.contains("wicket-authz"));
    // #322: the Lean spec, read by wicket-authz's oracle test.
    let s = select(&["verification/lean/Wicket/Glob.lean"]);
    assert!(s.affected.contains("wicket-authz") && s.suites.contains("lean"));
    check(
        &["plugins/wicket/skills/wicket-box/SKILL.md"],
        &["wicket-agent", "wicket-chan", "wicket-home", "wicket-node", "wicket-control", "wicket-cli"],
        &with(CLI, &["fuzz-manifest", "fuzz-chan"]),
    );
}

#[test]
fn end_to_end_scripts_select_their_suites() {
    check(&["verification/tla/GrantsOnNodes.tla", "verification/tla/README.md"], &[], &["tla"]);
    check(&["ci/acceptance/acp.yaml"], &[], &["acceptance", "acceptance-nodes"]);
    check(&["ci/smoke.sh"], &[], &["smoke"]);
    check(&["ci/h3get/src/main.rs"], &[], &["smoke", "acceptance"]);
    check(&["ci/kani.sh"], &[], &["kani"]);
    check(&["ci/update/x"], &[], &["update"]);
}

/// A glob naming one path (no wildcard) names one that exists: a rename mustn't leave it behind.
#[test]
fn literal_paths_exist() {
    let rules = rules().unwrap();
    let suites = Suites::parse(SUITES).unwrap();
    let globs = rules.path_rules.iter().flat_map(|r| r.globs.iter()).chain(suites.suites.iter().flat_map(|s| s.paths.iter()));
    let mut missing = Vec::new();
    for g in globs {
        // Paths for the future or the past: the rule says what a change there would mean.
        if ["rust-toolchain", ".cargo/**"].contains(&g.as_str()) || g.starts_with("fuzz/regressions/") {
            continue;
        }
        let lit: String = g.split(['*', '?', '[', '{']).next().unwrap().to_string();
        if !root().join(lit.trim_end_matches('/')).exists() && !lit.is_empty() {
            missing.push(g.clone());
        }
    }
    assert!(missing.is_empty(), "rules.toml or suites.toml names paths that don't exist: {missing:?}");
}

/// Every tracked file is in a crate or matched by a rule: none falls back to everything.
#[test]
fn every_tracked_file_is_claimed() {
    let r = root();
    let det = {
        let mut d = determinator::Determinator::new(head(), head());
        d.set_rules(&rules().unwrap()).unwrap();
        d
    };
    let files = git(&r, &["ls-files"]).unwrap();
    let unclaimed: Vec<&str> =
        files.lines().filter(|f| matches!(det.match_path(f, |_| ()), determinator::rules::PathMatch::NoMatches)).collect();
    assert!(unclaimed.is_empty(), "files no rule or crate claims (each selects everything): {unclaimed:?}");
}

/// (crate, path) for every file a crate's source names outside its own directory: string literals
/// with `../../` that resolve to an existing file or directory (relative to the source file or to
/// the crate). include_str! and include_bytes! arguments are such literals.
fn out_of_crate_inputs() -> BTreeSet<(String, String)> {
    let r = root();
    let mut found = BTreeSet::new();
    for p in head().workspace().iter() {
        let dir = p.manifest_path().parent().unwrap().canonicalize_utf8().unwrap();
        for src in rs_files(&dir) {
            let text = std::fs::read_to_string(&src).unwrap();
            for line in text.lines().filter(|l| l.contains("../..")) {
                for lit in line.split('"').skip(1).step_by(2).filter(|l| l.contains("../..")) {
                    let s = lit.split('{').next().unwrap().trim_end_matches('/');
                    for base in [src.parent().unwrap(), dir.as_path()] {
                        let Ok(abs) = base.join(s.trim_start_matches('/')).canonicalize_utf8() else { continue };
                        let Ok(rel) = abs.strip_prefix(&r) else { continue };
                        if !abs.starts_with(&dir) {
                            found.insert((p.name().to_string(), rel.to_string()));
                        }
                    }
                }
            }
        }
    }
    found
}

#[test]
fn every_out_of_crate_input_selects_its_crate() {
    let inputs = out_of_crate_inputs();
    assert!(inputs.iter().any(|(_, p)| p.starts_with("examples")), "the scan finds nothing: {inputs:?}");
    let mut fails = Vec::new();
    for (krate, path) in inputs {
        let probe = if root().join(&path).is_file() { path.clone() } else { format!("{path}/x") };
        let s = select(&[&probe]);
        if !s.everything && !s.affected.contains(&krate) {
            fails.push(format!("{krate} reads {path}, but a change to it doesn't select {krate}"));
        }
    }
    assert!(fails.is_empty(), "add them to ci/determinator/rules.toml: {fails:#?}");
}

#[test]
fn doctest_detection() {
    for (body, want) in [
        ("/// ```\n/// let x = 1;\n/// ```\nfn f() {}\n", true),
        ("//! ```rust,no_run\n//! x();\n//! ```\n", true),
        ("/// ```text\n/// out\n/// ```\n/// ```yaml\n/// a: 1\n/// ```\n", false),
        ("#![doc = include_str!(\"../README.md\")]\n", true),
        ("fn f() {} // ``` not a doc comment\n", false),
    ] {
        assert_eq!(text_has_doctests(body), want, "{body:?}");
    }
}

#[test]
fn the_suites_are_the_ones_the_gates_and_ci_run() {
    let suites = Suites::parse(SUITES).unwrap();
    let gates = std::fs::read_to_string(root().join("ci/gates.sh")).unwrap();
    let ci = std::fs::read_to_string(root().join(".github/workflows/ci.yml")).unwrap();
    for s in suites.names().filter(|s| !s.starts_with("fuzz-")) {
        assert!(gates.contains(&format!("has {s}")) || gates.contains(&format!("{s})")), "ci/gates.sh doesn't run {s}");
        if !["node-e2e", "acceptance-nodes", "update"].contains(&s) {
            assert!(ci.contains(&format!("' {s} '")) || s == "policy", ".github/workflows/ci.yml doesn't run {s}");
        }
    }
    let dir: BTreeSet<String> = std::fs::read_dir(root().join("fuzz/fuzz_targets"))
        .unwrap()
        .map(|e| Utf8PathBuf::from_path_buf(e.unwrap().path()).unwrap().file_stem().unwrap().to_string())
        .collect();
    assert_eq!(suites.fuzz_targets.iter().cloned().collect::<BTreeSet<_>>(), dir, "suites.toml's fuzz targets");
}
