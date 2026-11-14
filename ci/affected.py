#!/usr/bin/env python3
"""Which tests a change can affect (#218): changed files -> workspace crates -> their reverse
dependencies, and changed files -> end-to-end suites, from the table in ci/affected.map.

    ci/affected.py [--base REF] [--worktree] [--files FILE|-] [--github-output FILE] [--self-test]

  --base REF       compare with the merge base of REF and HEAD (default origin/main)
  --worktree       also uncommitted and untracked files (local gates, before a commit)
  --files FILE|-   the changed paths, one per line, instead of asking git
  --github-output  append crates=, all_crates=, suites= and rust= to this file (GitHub Actions)
  --self-test      check the mapping on synthetic changes, and that the table covers every file a
                   crate reads from outside its own directory

It fails towards everything: an error, an unknown base, an empty change or a file no rule maps
selects every crate and every suite. Changes to the selection itself (this script, the table,
ci/gates.sh, .github/) select everything, so a change can't switch off its own tests.
"""
import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TABLE = ROOT / "ci" / "affected.map"
# Every end-to-end suite the table can name, in the order they run.
SUITES = ["docs", "cli-ref", "policy", "smoke", "hibernate", "restore", "acceptance", "daemon-uids", "install-test",
          "node-e2e", "acceptance-nodes", "update"]
ALL = "all"
# Crates with a library target (doctests run only on those), filled by workspace().
LIBS = set()


def workspace():
    """{crate: directory relative to ROOT} and {crate: crates it depends on} (normal, dev and build)."""
    out = subprocess.run(["cargo", "metadata", "--format-version", "1", "--no-deps", "--offline"], cwd=ROOT,
                         check=True, capture_output=True, text=True).stdout
    m = json.loads(out)
    dirs = {p["name"]: str(Path(p["manifest_path"]).parent.relative_to(ROOT)) for p in m["packages"]}
    global LIBS
    LIBS = {p["name"] for p in m["packages"] if any("lib" in t["kind"] for t in p["targets"])}
    deps = {p["name"]: {d["name"] for d in p["dependencies"] if d["name"] in dirs and d["name"] != p["name"]}
            for p in m["packages"]}
    return dirs, deps


def load_table(path=TABLE):
    """Rules: (pattern, crates or ALL, suites or ALL). `-` is none."""
    rules = []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 3:
            raise ValueError(f"{path.name}:{n}: want `pattern | crates | suites`")
        pat, crates, suites = parts
        cs = ALL if crates == ALL else set() if crates == "-" else set(crates.split())
        ss = ALL if suites == ALL else set() if suites == "-" else set(suites.split())
        if ss != ALL and not ss <= set(SUITES):
            raise ValueError(f"{path.name}:{n}: unknown suite(s) {sorted(ss - set(SUITES))}")
        rules.append((pat, cs, ss))
    return rules


def matches(pat, path):
    """Globs where `**` crosses directories and `*` doesn't; a pattern without a slash matches the
    file name anywhere."""
    if "/" not in pat:
        return fnmatch.fnmatchcase(path.rsplit("/", 1)[-1], pat)
    rx = ""
    i = 0
    while i < len(pat):
        if pat.startswith("**/", i):
            rx += "(?:.*/)?"
            i += 3
        elif pat.startswith("**", i):
            rx += ".*"
            i += 2
        elif pat[i] == "*":
            rx += "[^/]*"
            i += 1
        elif pat[i] == "?":
            rx += "[^/]"
            i += 1
        else:
            rx += re.escape(pat[i])
            i += 1
    return re.fullmatch(rx, path) is not None


def closure(crates, deps):
    """`crates` and every crate that depends on one of them, directly or not."""
    rev = {c: set() for c in deps}
    for c, ds in deps.items():
        for d in ds:
            rev.setdefault(d, set()).add(c)
    seen, todo = set(), list(crates)
    while todo:
        c = todo.pop()
        if c in seen:
            continue
        seen.add(c)
        todo.extend(rev.get(c, ()))
    return seen


def select(files, dirs, deps, rules):
    """(crates, suites, why): sets of names, or ALL, and a line per file saying what it selected."""
    if not files:
        return ALL, ALL, ["no changed files: everything"]
    crates, suites, why = set(), set(), []
    for f in files:
        owner = next((c for c, d in dirs.items() if f.startswith(d + "/")), None)
        hit = [(p, cs, ss) for p, cs, ss in rules if matches(p, f)]
        fc = set() if owner is None else {owner}
        fs = set()
        for _, cs, ss in hit:
            fc = ALL if cs == ALL or fc == ALL else fc | cs
            fs = ALL if ss == ALL or fs == ALL else fs | ss
        if not hit:
            # Unmapped: in a crate, its crates' tests and every suite; elsewhere, everything.
            fc = fc if owner else ALL
            fs = ALL
        why.append(f"{f}: crates {'all' if fc == ALL else ' '.join(sorted(fc)) or '-'}; "
                   f"suites {'all' if fs == ALL else ' '.join(s for s in SUITES if s in fs) or '-'}"
                   + ("" if hit else " (no rule)"))
        crates = ALL if fc == ALL or crates == ALL else crates | fc
        suites = ALL if fs == ALL or suites == ALL else suites | fs
    if crates != ALL:
        unknown = crates - set(dirs)
        if unknown:
            raise ValueError(f"the table names crates that aren't in the workspace: {sorted(unknown)}")
        crates = closure(crates, deps)
        if crates >= set(dirs):
            crates = ALL
    if suites != ALL and set(SUITES) <= suites:
        suites = ALL
    return crates, suites, why


def cargo_args(crates):
    """Cargo's package arguments for `crates`: `--workspace` for all, `-p` per crate, or none."""
    if crates == ALL:
        return "--workspace"
    return " ".join(f"-p {c}" for c in sorted(crates))


def doc_args(crates):
    """The same for doctests: the tests' own package set, so cargo resolves the same features and
    reuses what the tests built (a smaller set rebuilds every dependency: 2–6 minutes). Empty when
    no selected crate has a library, which `cargo test --doc` refuses; a bin-only crate alongside a
    library is fine."""
    if crates == ALL:
        return "--workspace"
    return cargo_args(crates) if crates & LIBS else ""


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True).stdout


def changed(base, worktree):
    mb = git("merge-base", base, "HEAD").strip()
    files = set(git("diff", "--no-renames", "--name-only", f"{mb}...HEAD").split())
    if worktree:
        files |= set(git("diff", "--no-renames", "--name-only", "HEAD").split())
        files |= set(git("ls-files", "--others", "--exclude-standard").split())
    return sorted(files)


def show(crates, suites):
    c = "all" if crates == ALL else " ".join(sorted(crates))
    s = "all" if suites == ALL else " ".join(x for x in SUITES if x in suites)
    return c, s


# ---- self-test ----

def out_of_crate_inputs(dirs):
    """(crate, path) for every file a crate's source names outside its own directory: include_str!
    and include_bytes! arguments, and string literals with `../../` that resolve to an existing file
    or directory (relative to the source file or to the crate)."""
    found = set()
    lit = re.compile(r'"([^"\n]*\.\./\.\.[^"\n]*)"')
    for crate, d in dirs.items():
        cdir = ROOT / d
        for src in cdir.rglob("*.rs"):
            if "target" in src.relative_to(cdir).parts:
                continue
            for m in lit.finditer(src.read_text(errors="replace")):
                s = m.group(1).split("{")[0].rstrip("/")
                for base in (src.parent, cdir):
                    p = (base / s.lstrip("/")).resolve()
                    try:
                        rel = p.relative_to(ROOT)
                    except ValueError:
                        continue
                    if p.exists() and not str(rel).startswith(d + "/") and str(rel) != d:
                        found.add((crate, str(rel)))
    return sorted(found)


def self_test():
    dirs, deps = workspace()
    rules = load_table()
    fails = []

    def case(name, files, want_crates, want_suites):
        c, s, _ = select(files, dirs, deps, rules)
        for what, got, want in (("crates", c, want_crates), ("suites", s, want_suites)):
            ok = want(got) if callable(want) else got == want
            if not ok:
                fails.append(f"{name}: {what} {show(c, s)[0 if what == 'crates' else 1]!r}")

    case("docs only", ["docs/reference/agents.md", "README.md", "experiments/x/RESULTS.md"], set(), {"docs"})
    case("the CLI reference", ["docs/reference/cli.md"], set(), {"docs", "cli-ref"})
    case("wicket-fwd", ["crates/wicket-fwd/src/copy.rs"], {"wicket-fwd", "wicket-proxy", "wicket-cli"}, {"smoke"})
    # Nearly everything: the crates that don't depend on wicket-core (auth, identity, fwd, placement) aren't.
    case("wicket-core", ["crates/wicket-core/src/op.rs"],
         lambda c: c != ALL and len(c) >= 10 and {"wicket-core", "wicket-cli", "wicket-proxy"} <= c and "wicket-fwd" not in c, ALL)
    case("a crate's own tests", ["crates/wicket-sandbox/tests/x.rs"], {"wicket-sandbox", "wicket-cli"}, set())
    case("policy code", ["crates/wicket-policy/tests/cedar.rs"], {"wicket-policy", "wicket-policy-diff", "wicket-cli"}, {"policy"})
    case("hibernation", ["crates/wicket-cli/src/hibernate.rs"], {"wicket-cli"}, {"hibernate", "restore"})
    case("updates", ["crates/wicket-cli/src/update.rs"], {"wicket-cli"}, {"update"})
    case("the node protocol", ["crates/wicket-cli/src/chan.rs"], {"wicket-cli"}, ALL)
    case("a CLI command group", ["crates/wicket-cli/src/cmd/itself.rs"], {"wicket-cli"}, {"cli-ref", "update"})
    case("the run commands (nearly every suite calls them)", ["crates/wicket-cli/src/cmd/run.rs"], {"wicket-cli"}, ALL)
    case("the lockfile", ["Cargo.lock"], ALL, ALL)
    case("the toolchain", ["rust-toolchain.toml"], ALL, ALL)
    case("a crate manifest", ["crates/wicket-fwd/Cargo.toml"], ALL, ALL)
    case("the selection itself", ["ci/affected.map"], ALL, ALL)
    case("a workflow", [".github/workflows/ci.yml"], ALL, ALL)
    case("an unmapped file", ["somewhere/new.txt"], ALL, ALL)
    case("nothing changed", [], ALL, ALL)
    case("a deleted crate file", ["crates/wicket-sandbox/src/gone.rs"], {"wicket-sandbox", "wicket-cli"}, ALL)
    case("an example zone", ["examples/demo.yaml"], lambda c: c != ALL and {"wicket-core", "wicket-authz", "wicket-feed"} <= c,
         set())
    case("the agent image", ["images/claude-code/wicket-entry"], {"wicket-cli"}, lambda s: s != ALL and "smoke" in s)
    case("a test the feed includes", ["crates/wicket-authz/tests/common/mod.rs"], lambda c: c != ALL and "wicket-feed" in c,
         set())
    case("an acceptance scenario", ["ci/acceptance/acp.yaml"], set(), {"acceptance", "acceptance-nodes"})
    # A rule naming one path (no wildcard) names one that exists: a rename mustn't leave it behind.
    for pat, _, _ in rules:
        if "/" in pat and not any(ch in pat for ch in "*?[") and not (ROOT / pat).exists():
            fails.append(f"ci/affected.map names {pat}, which doesn't exist")
    # Cargo's arguments: crates without a library get no doctest arguments, and none selected is none.
    for files, want_args, want_doc in (
        (["crates/wicket-cli/src/chan.rs"], "-p wicket-cli", ""),
        (["crates/wicket-fwd/src/copy.rs"], "-p wicket-cli -p wicket-fwd -p wicket-proxy", "-p wicket-cli -p wicket-fwd -p wicket-proxy"),
        (["docs/x.md"], "", ""),
        (["Cargo.lock"], "--workspace", "--workspace"),
    ):
        c, _, _ = select(files, dirs, deps, rules)
        if (cargo_args(c), doc_args(c)) != (want_args, want_doc):
            fails.append(f"cargo arguments for {files}: {cargo_args(c)!r} / {doc_args(c)!r}, want {want_args!r} / {want_doc!r}")
    # Every file a crate reads from outside its directory is mapped to that crate.
    for crate, path in out_of_crate_inputs(dirs):
        probe = path if (ROOT / path).is_file() else path + "/x"
        c, _, _ = select([probe], dirs, deps, rules)
        if c != ALL and crate not in c:
            fails.append(f"{crate} reads {path}, but a change to it doesn't select {crate}: add it to ci/affected.map")
    for f in fails:
        print("FAIL", f)
    print(f"affected self-test: {'ok' if not fails else f'{len(fails)} failure(s)'}")
    return 1 if fails else 0


def main(argv):
    base, worktree, files_from, gh_out = "origin/main", False, None, None
    it = iter(argv)
    for a in it:
        if a == "--base":
            base = next(it)
        elif a == "--worktree":
            worktree = True
        elif a == "--files":
            files_from = next(it)
        elif a == "--github-output":
            gh_out = next(it)
        elif a == "--self-test":
            return self_test()
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            print(f"unknown argument {a}", file=sys.stderr)
            return 2
    try:
        if files_from is not None:
            text = sys.stdin.read() if files_from == "-" else Path(files_from).read_text()
            files = sorted({ln.strip() for ln in text.splitlines() if ln.strip()})
        else:
            files = changed(base, worktree)
        dirs, deps = workspace()
        crates, suites, why = select(files, dirs, deps, load_table())
    except Exception as e:  # noqa: BLE001 - any failure selects everything
        print(f"affected: {e}; selecting everything", file=sys.stderr)
        crates, suites, why = ALL, ALL, [f"error: {e}"]
    c, s = show(crates, suites)
    # Doctests run over the tests' crates (the same features), when one of them has a library.
    docs = "all" if crates == ALL else (" ".join(sorted(crates)) if crates & LIBS else "")
    for w in why:
        print(f"  {w}", file=sys.stderr)
    print(f"crates: {c}")
    print(f"suites: {s}")
    print(f"doc crates: {docs}")
    if gh_out:
        with open(gh_out, "a") as f:
            f.write(f"crates={'' if crates == ALL else c}\n")
            f.write(f"all_crates={'true' if crates == ALL else 'false'}\n")
            # The selected crates with a library: doctests (`cargo test --doc` refuses a crate without one).
            f.write(f"doc_crates={'' if crates == ALL else docs}\n")
            # Cargo's package arguments, ready to use; empty when nothing is selected.
            f.write(f"args={cargo_args(crates)}\n")
            f.write(f"doc_args={doc_args(crates)}\n")
            # The Rust job: for the selected crates, and for the CLI reference check (which builds wicket-cli).
            rust = crates == ALL or bool(crates) or suites == ALL or "cli-ref" in suites
            f.write(f"rust={'true' if rust else 'false'}\n")
            # Space-padded, so a workflow can test ` smoke ` with contains().
            # An empty value means "run everything" to the workflow, so no suite is ` none `.
            f.write(f"suites= {' '.join(SUITES) if suites == ALL else (s or 'none')} \n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
