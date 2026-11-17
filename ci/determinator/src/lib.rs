//! What a change can affect (#218): the workspace crates guppy's determinator marks changed (by the
//! paths that changed, rules.toml, and the simulated builds before and after a manifest or lockfile
//! change), the crates affected through them, a nextest filterset for their tests, and the suites in
//! suites.toml. It fails towards everything: a rule marking everything, a path no rule or crate
//! claims, an empty change or an error selects every crate and every suite.

use anyhow::{bail, Context, Result};
use camino::{Utf8Path, Utf8PathBuf};
use determinator::rules::{DeterminatorRules, PathMatch};
use determinator::Determinator;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use guppy::graph::{BuildTargetId, DependencyDirection, PackageGraph};
use guppy::MetadataCommand;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub const RULES: &str = include_str!("../rules.toml");
pub const SUITES: &str = include_str!("../suites.toml");

pub fn rules() -> Result<DeterminatorRules> {
    DeterminatorRules::parse(RULES).context("ci/determinator/rules.toml")
}

/// The workspace's package graph, from `cargo metadata` in `dir`.
pub fn graph(dir: &Utf8Path) -> Result<PackageGraph> {
    let mut cmd = MetadataCommand::new();
    cmd.current_dir(dir).other_options(["--locked"]);
    cmd.build_graph().with_context(|| format!("cargo metadata in {dir}"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuitesFile {
    /// Files only a crate's tests read: a change to them can't change what the crate builds.
    tests: TestsFile,
    suite: BTreeMap<String, Entry>,
    fuzz: FuzzFile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TestsFile {
    paths: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FuzzFile {
    paths: Vec<String>,
    target: BTreeMap<String, Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    #[serde(default)]
    packages: Vec<String>,
    #[serde(default)]
    paths: Vec<String>,
    /// The suite runs the built binaries, not the crates' tests: a change only to tests (the
    /// `[tests]` paths) doesn't select it through its packages.
    #[serde(default)]
    binary: bool,
}

pub struct Suite {
    pub name: String,
    pub packages: Vec<String>,
    pub paths: Vec<String>,
    /// It runs the built binaries (see `Entry::binary`).
    pub binary: bool,
    globs: GlobSet,
}

impl Suite {
    fn new(name: String, e: Entry) -> Result<Self> {
        Ok(Suite { globs: globs(&e.paths, &name)?, name, packages: e.packages, paths: e.paths, binary: e.binary })
    }

    pub fn matches(&self, path: &Utf8Path) -> bool {
        self.globs.is_match(path.as_std_path())
    }
}

fn globs(paths: &[String], what: &str) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in paths {
        b.add(GlobBuilder::new(p).literal_separator(true).build().with_context(|| format!("{what}: {p}"))?);
    }
    Ok(b.build()?)
}

/// The suites, end-to-end first, then `fuzz-<target>` for each fuzz target.
pub struct Suites {
    pub suites: Vec<Suite>,
    pub fuzz_targets: Vec<String>,
    /// The `[tests]` paths: files only a crate's tests read.
    pub tests: Vec<String>,
    test_globs: GlobSet,
}

impl Suites {
    pub fn parse(text: &str) -> Result<Self> {
        let f: SuitesFile = toml::from_str(text).context("ci/determinator/suites.toml")?;
        let mut suites = Vec::new();
        for (name, e) in f.suite {
            suites.push(Suite::new(name, e)?);
        }
        let fuzz_targets: Vec<String> = f.fuzz.target.keys().cloned().collect();
        for (t, mut e) in f.fuzz.target {
            let mut paths: Vec<String> = f.fuzz.paths.iter().map(|p| p.replace("{t}", &t)).collect();
            paths.append(&mut e.paths);
            e.paths = paths;
            suites.push(Suite::new(format!("fuzz-{t}"), e)?);
        }
        Ok(Suites { suites, fuzz_targets, test_globs: globs(&f.tests.paths, "tests")?, tests: f.tests.paths })
    }

    /// Whether only a crate's tests read `path`.
    pub fn is_test(&self, path: &Utf8Path) -> bool {
        self.test_globs.is_match(path.as_std_path())
    }

    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.suites.iter().map(|s| s.name.as_str())
    }
}

/// What a change selects.
#[derive(Debug, Default)]
pub struct Selection {
    /// Every crate and every suite.
    pub everything: bool,
    /// A line per changed path: what it marked.
    pub why: Vec<String>,
    /// The crates marked changed, by their paths, the rules or their simulated builds.
    pub changed: BTreeSet<String>,
    /// The changed crates and every crate depending on one: the crates to build, lint and test.
    pub affected: BTreeSet<String>,
    /// The crates whose rdeps() the nextest filterset names: together they cover `affected`.
    pub roots: BTreeSet<String>,
    /// `affected` through the changed files that aren't only tests (`Suites::is_test`), and the
    /// simulated builds: what the suites that run the built binaries see change.
    pub built: BTreeSet<String>,
    pub suites: BTreeSet<String>,
}

fn names<'g>(set: &guppy::graph::PackageSet<'g>) -> BTreeSet<String> {
    set.packages(DependencyDirection::Forward).filter(|p| p.in_workspace()).map(|p| p.name().to_string()).collect()
}

impl Selection {
    pub fn everything(why: Vec<String>) -> Self {
        Selection { everything: true, why, ..Default::default() }
    }

    /// `old` is the workspace before the change (the same graph as `new` when no manifest or
    /// lockfile changed), `new` after it.
    pub fn compute(
        old: &PackageGraph,
        new: &PackageGraph,
        files: &[Utf8PathBuf],
        rules: &DeterminatorRules,
        suites: &Suites,
    ) -> Result<Self> {
        if files.is_empty() {
            return Ok(Self::everything(vec!["no changed files: everything".into()]));
        }
        for s in &suites.suites {
            for p in &s.packages {
                new.workspace().member_by_name(p).with_context(|| format!("suite {}: no crate {p}", s.name))?;
            }
        }
        let mut det = Determinator::new(old, new);
        det.set_rules(rules)?;
        let mut why = Vec::new();
        let mut everything = false;
        // The crates marked by files that aren't only tests: what the built binaries see change.
        let mut code = BTreeSet::new();
        for f in files {
            let mut marked = BTreeSet::new();
            let m = det.match_path(f, |id| {
                marked.insert(new.metadata(id).map(|p| p.name().to_string()).unwrap_or_default());
            });
            let what = match m {
                PathMatch::RuleMatchedAll => "everything (a rule)".to_string(),
                PathMatch::NoMatches => "everything (no rule, in no crate)".to_string(),
                _ if marked.is_empty() => "no crate".to_string(),
                _ => marked.iter().cloned().collect::<Vec<_>>().join(" "),
            };
            everything |= matches!(m, PathMatch::RuleMatchedAll | PathMatch::NoMatches);
            let test = suites.is_test(f);
            if !test {
                code.extend(marked.iter().filter(|n| !n.is_empty()).cloned());
            }
            why.push(format!("{f}: {what}{}", if test && !marked.is_empty() { " (its tests only)" } else { "" }));
        }
        if everything {
            return Ok(Self::everything(why));
        }
        det.add_changed_paths(files.iter().map(|p| p.as_path()));
        let set = det.compute();
        for p in names(&set.summary_changed_set) {
            why.push(format!("{p}: its simulated build changed"));
        }
        let changed: BTreeSet<String> = names(&set.path_changed_set).union(&names(&set.summary_changed_set)).cloned().collect();
        let affected = names(&set.affected_set);
        // The filter's roots: each changed crate that no other changed crate's rdeps() already
        // covers, and any crate a package rule marked that Cargo's dependencies don't reach.
        let rdeps = |of: &mut dyn Iterator<Item = &String>| -> Result<BTreeSet<String>> {
            let ids: Vec<_> = of.filter_map(|n| new.workspace().member_by_name(n).ok()).map(|p| p.id()).collect();
            Ok(names(&new.query_reverse(ids)?.resolve()))
        };
        let reached = rdeps(&mut changed.iter())?;
        let mut roots: BTreeSet<String> = affected.difference(&reached).cloned().collect();
        for c in &changed {
            if !rdeps(&mut changed.iter().filter(|o| *o != c))?.contains(c) {
                roots.insert(c.clone());
            }
        }
        // Two changed crates in a cycle (through a dev-dependency) cover each other: name both.
        if !rdeps(&mut roots.iter())?.is_superset(&affected) {
            roots.extend(changed.iter().cloned());
        }
        // What the built binaries see change: the crates code marked, and those whose simulated
        // build changed, and every crate depending on one.
        code.extend(names(&set.summary_changed_set));
        let built = if code.is_empty() { BTreeSet::new() } else { rdeps(&mut code.iter())? };
        let suites = suites
            .suites
            .iter()
            .filter(|s| {
                let through = if s.binary { &built } else { &affected };
                files.iter().any(|f| s.matches(f)) || s.packages.iter().any(|p| through.contains(p))
            })
            .map(|s| s.name.clone())
            .collect();
        Ok(Selection { everything: false, why, changed, affected, roots, built, suites })
    }

    /// Cargo's package arguments: `--workspace` for every crate, `-p` per crate, or none.
    pub fn cargo_args(&self, all: &BTreeSet<String>) -> String {
        if self.everything || (!all.is_empty() && self.affected == *all) {
            return "--workspace".into();
        }
        self.affected.iter().map(|c| format!("-p {c}")).collect::<Vec<_>>().join(" ")
    }

    /// nextest's filterset (`-E`): the tests of rdeps() of each root, all() for everything, empty
    /// when no crate is selected.
    pub fn filter(&self) -> String {
        if self.everything {
            return "all()".into();
        }
        self.roots.iter().map(|c| format!("rdeps(={c})")).collect::<Vec<_>>().join(" | ")
    }

    pub fn has_suite(&self, s: &str) -> bool {
        self.everything || self.suites.contains(s)
    }
}

/// The workspace crates' names.
pub fn members(g: &PackageGraph) -> BTreeSet<String> {
    g.workspace().iter().map(|p| p.name().to_string()).collect()
}

/// The crates (of `among`, or every one) with a library whose sources have a doctest: rustdoc's
/// step would otherwise build for nothing, and refuses a crate without a library.
pub fn doctest_crates(g: &PackageGraph, among: Option<&BTreeSet<String>>) -> BTreeSet<String> {
    g.workspace()
        .iter()
        .filter(|p| among.is_none_or(|a| a.contains(p.name())))
        .filter(|p| p.build_target(&BuildTargetId::Library).is_some())
        .filter(|p| p.manifest_path().parent().is_some_and(has_doctests))
        .map(|p| p.name().to_string())
        .collect()
}

// Code block languages rustdoc doesn't run as doctests.
const NOT_RUST: &[&str] = &[
    "text",
    "txt",
    "ignore",
    "sh",
    "bash",
    "console",
    "shell",
    "yaml",
    "yml",
    "json",
    "toml",
    "markdown",
    "md",
    "sql",
    "html",
    "xml",
    "diff",
    "cedar",
    "python",
    "js",
    "javascript",
    "dockerfile",
    "ini",
    "http",
];

/// Whether a crate's sources have a doc-comment code block rustdoc would run (or pull docs from a
/// file, which might). Fences are paired, so a closing ``` isn't taken for an opening one.
pub fn has_doctests(dir: &Utf8Path) -> bool {
    rs_files(dir).iter().any(|f| std::fs::read_to_string(f).is_ok_and(|t| text_has_doctests(&t)))
}

pub fn text_has_doctests(text: &str) -> bool {
    let mut open = false;
    for line in text.lines() {
        let l = line.trim_start();
        if (l.starts_with("#![doc") || l.starts_with("#[doc")) && l.contains("include_str!") {
            return true;
        }
        let Some(rest) = l.strip_prefix("///").or_else(|| l.strip_prefix("//!")) else { continue };
        let Some(lang) = rest.trim_start().strip_prefix("```") else { continue };
        if open {
            open = false;
            continue;
        }
        open = true;
        let langs: Vec<&str> = lang.trim_start_matches('`').split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        if langs.is_empty() || langs.contains(&"rust") || !langs.iter().any(|l| NOT_RUST.contains(l)) {
            return true;
        }
    }
    false
}

/// The `.rs` files under `dir`, outside any `target` directory.
pub fn rs_files(dir: &Utf8Path) -> Vec<Utf8PathBuf> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        let Ok(rd) = d.read_dir_utf8() else { continue };
        for e in rd.flatten() {
            let p = e.path().to_path_buf();
            if p.is_dir() {
                if e.file_name() != "target" {
                    todo.push(p);
                }
            } else if p.extension() == Some("rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// `git` in `root`, its output.
pub fn git(root: &Utf8Path, args: &[&str]) -> Result<String> {
    let out = std::process::Command::new("git").current_dir(root).args(args).output()?;
    if !out.status.success() {
        bail!("git {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8(out.stdout)?)
}

/// The paths changed since the merge base of `base` and HEAD (and, with `worktree`, uncommitted and
/// untracked ones), and that merge base.
pub fn changed(root: &Utf8Path, base: &str, worktree: bool) -> Result<(Vec<Utf8PathBuf>, String)> {
    let mb = git(root, &["merge-base", base, "HEAD"])?.trim().to_string();
    let mut files: BTreeSet<String> =
        git(root, &["diff", "--no-renames", "--name-only", &format!("{mb}...HEAD")])?.lines().map(String::from).collect();
    if worktree {
        files.extend(git(root, &["diff", "--no-renames", "--name-only", "HEAD"])?.lines().map(String::from));
        files.extend(git(root, &["ls-files", "--others", "--exclude-standard"])?.lines().map(String::from));
    }
    Ok((files.into_iter().filter(|f| !f.is_empty()).map(Utf8PathBuf::from).collect(), mb))
}

/// Whether the change touches a manifest or the lockfile: the determinator then compares the
/// simulated builds of the workspace before the change with those after it.
pub fn touches_manifests(files: &[Utf8PathBuf]) -> bool {
    files.iter().any(|f| matches!(f.file_name(), Some("Cargo.toml" | "Cargo.lock")) && !f.starts_with("fuzz"))
}

/// The workspace's package graph at `rev`, from a temporary worktree.
pub fn graph_at(root: &Utf8Path, rev: &str) -> Result<PackageGraph> {
    let dir = Utf8PathBuf::from_path_buf(std::env::temp_dir())
        .map_err(|p| anyhow::anyhow!("temporary directory {} isn't UTF-8", p.display()))?
        .join(format!("wicket-affected-{}", std::process::id()));
    git(root, &["worktree", "add", "--detach", "--quiet", dir.as_str(), rev])?;
    let g = graph(&dir);
    let _ = git(root, &["worktree", "remove", "--force", dir.as_str()]);
    g
}
