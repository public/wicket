//! What a change can affect (#218). Run from the repository:
//!
//!     cargo run -q --locked --manifest-path ci/determinator/Cargo.toml -- \
//!         [--base REF] [--worktree] [--files FILE|-] [--github-output FILE]
//!
//!   --base REF       compare with the merge base of REF and HEAD (default origin/main)
//!   --worktree       also uncommitted and untracked files (local gates, before a commit)
//!   --files FILE|-   the changed paths, one per line, instead of asking git (with no base to
//!                    compare manifests with: a manifest or the lockfile among them is everything)
//!   --github-output  append the selection to this file (GitHub Actions; see `outputs`)
//!
//! It prints the selection as `key=value` lines (the same as --github-output), and on stderr what
//! each changed path marked. Any error selects everything.

use anyhow::{bail, Result};
use camino::{Utf8Path, Utf8PathBuf};
use std::collections::BTreeSet;
use std::io::Read;
use wicket_affected::*;

struct Args {
    base: String,
    worktree: bool,
    files: Option<String>,
    github_output: Option<String>,
}

fn parse_args() -> Result<Args> {
    let mut a = Args { base: "origin/main".into(), worktree: false, files: None, github_output: None };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut val = || it.next().ok_or_else(|| anyhow::anyhow!("{arg} wants a value"));
        match arg.as_str() {
            "--base" => a.base = val()?,
            "--worktree" => a.worktree = true,
            "--files" => a.files = Some(val()?),
            "--github-output" => a.github_output = Some(val()?),
            "-h" | "--help" => {
                println!("see ci/determinator/src/main.rs");
                std::process::exit(0);
            }
            _ => bail!("unknown argument {arg}"),
        }
    }
    Ok(a)
}

fn select(args: &Args, root: &Utf8Path, suites: &Suites) -> Result<(Selection, BTreeSet<String>, String)> {
    let (files, base) = match &args.files {
        Some(f) => {
            let mut text = String::new();
            if f == "-" {
                std::io::stdin().read_to_string(&mut text)?;
            } else {
                text = std::fs::read_to_string(f)?;
            }
            let set: BTreeSet<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
            (set.into_iter().map(Utf8PathBuf::from).collect::<Vec<_>>(), None)
        }
        None => {
            let (files, mb) = changed(root, &args.base, args.worktree)?;
            (files, Some(mb))
        }
    };
    let new = graph(root)?;
    let all = members(&new);
    let rules = rules()?;
    let old = match (touches_manifests(&files), base) {
        (false, _) => None,
        (true, Some(mb)) => Some(graph_at(root, &mb)?),
        (true, None) => {
            let why = vec!["a manifest or the lockfile, and no base to compare it with: everything".into()];
            return Ok((Selection::everything(why), all, doc_args(&new, None)));
        }
    };
    let sel = Selection::compute(old.as_ref().unwrap_or(&new), &new, &files, &rules, suites)?;
    let docs = doc_args(&new, Some(&sel));
    Ok((sel, all, docs))
}

/// Doctests run over the tests' own crates (the same features, so cargo reuses what the tests
/// built), when one of them has a doctest.
fn doc_args(g: &guppy::graph::PackageGraph, sel: Option<&Selection>) -> String {
    let among = sel.filter(|s| !s.everything).map(|s| &s.affected);
    if doctest_crates(g, among).is_empty() {
        return String::new();
    }
    match sel {
        Some(s) if !s.everything => s.cargo_args(&members(g)),
        _ => "--workspace".into(),
    }
}

fn main() -> Result<()> {
    let args = parse_args()?;
    let root = Utf8PathBuf::from(git(Utf8Path::new("."), &["rev-parse", "--show-toplevel"])?.trim());
    let suites = Suites::parse(SUITES)?;
    let (sel, all, docs) = select(&args, &root, &suites).unwrap_or_else(|e| {
        eprintln!("affected: {e:#}; selecting everything");
        (Selection::everything(vec![format!("error: {e:#}")]), BTreeSet::new(), "--workspace".into())
    });
    for w in &sel.why {
        eprintln!("  {w}");
    }
    let suite_names: Vec<&str> = suites.names().filter(|s| sel.has_suite(s)).collect();
    let fuzz: Vec<&str> = suites.fuzz_targets.iter().map(String::as_str).filter(|t| sel.has_suite(&format!("fuzz-{t}"))).collect();
    let args_ = sel.cargo_args(&all);
    let out = [
        ("all_crates", (args_ == "--workspace").to_string()),
        ("crates", if sel.everything { "all".into() } else { sel.affected.iter().cloned().collect::<Vec<_>>().join(" ") }),
        // Cargo's package arguments, ready to use; empty when no crate is selected.
        ("args", args_.clone()),
        // nextest's -E filterset for those crates' tests.
        ("filter", sel.filter()),
        ("doc_args", docs),
        ("rust", (!args_.is_empty()).to_string()),
        // Space-padded, so a workflow can test ` smoke ` with contains(). An empty value means
        // "run everything" to the workflow, so no suite is ` none `.
        ("suites", format!(" {} ", if suite_names.is_empty() { "none".into() } else { suite_names.join(" ") })),
        // The fuzz targets to run (ci/fuzz.sh's arguments); `none` when none.
        ("fuzz", if fuzz.is_empty() { "none".into() } else { fuzz.join(" ") }),
    ];
    let text: String = out.iter().map(|(k, v)| format!("{k}={v}\n")).collect();
    print!("{text}");
    if let Some(f) = &args.github_output {
        use std::io::Write;
        std::fs::OpenOptions::new().append(true).create(true).open(f)?.write_all(text.as_bytes())?;
    }
    Ok(())
}
