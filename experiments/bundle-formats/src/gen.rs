//! Deterministic datasets and sessions (E5). Nothing here is checked in as data: the same seed always
//! gives the same bytes, so the results can be regenerated.
//!
//! - `rust`: a Rust repository (sources, `Cargo.lock`) with a `target/` of build outputs (rlibs,
//!   incremental caches, build-script outputs, a binary). A session edits a few sources and rebuilds:
//!   a small share of the build outputs is rewritten, some incremental files are added and removed.
//! - `node`: a Node repository with `node_modules` (thousands of small JS/JSON files, some packages
//!   in two versions that share most files). A session edits sources; every fifth upgrades a package.
//! - `home`: an agent's `$HOME` with Claude Code state: `~/.claude/projects/*/*.jsonl` session logs
//!   (append-only), todos, shell history, a cache. A session appends to the current log; every fifth
//!   starts a new one.
//! - `small`: a small-file-heavy tree (tens of thousands of files under 2 KB). A session edits 1%,
//!   adds 0.5% and deletes 0.2%.
//!
//! Content mimics what compresses and dedups like the real thing: source text from a word list,
//! "binary" build outputs from random runs mixed with repeated sections (zstd -3 gets them to about
//! 40-50%), JSON lines with repeated keys.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::io::Write;
use std::path::Path;

const WORDS: &[&str] = &[
    "fn", "let", "mut", "impl", "struct", "enum", "match", "self", "Some", "None", "Ok", "Err", "return", "pub", "use", "crate",
    "async", "await", "where", "for", "in", "if", "else", "loop", "while", "const", "static", "trait", "type", "move", "ref",
    "value", "result", "error", "config", "state", "buffer", "index", "count", "node", "tree", "path", "key", "data", "request",
    "response", "handler", "client", "server", "token", "grant", "zone", "box", "agent", "session", "store", "bundle", "manifest",
];

fn rng(seed: &str) -> ChaCha8Rng {
    use sha2::Digest;
    let d = sha2::Sha256::digest(seed.as_bytes());
    ChaCha8Rng::from_seed(d.into())
}

fn text(r: &mut ChaCha8Rng, bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes + 64);
    let mut col = 0;
    while out.len() < bytes {
        let w = WORDS[r.gen_range(0..WORDS.len())];
        out.extend_from_slice(w.as_bytes());
        col += w.len() + 1;
        if col > 70 || r.gen_ratio(1, 12) {
            out.push(b'\n');
            col = 0;
            if r.gen_ratio(1, 4) {
                out.extend_from_slice(b"    ");
            }
        } else {
            out.push(if r.gen_ratio(1, 9) { b'(' } else { b' ' });
        }
    }
    out.truncate(bytes);
    out
}

/// Build-output-like bytes: random runs and repeats of earlier runs (zstd -3 gets about half).
fn binary(r: &mut ChaCha8Rng, bytes: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(bytes);
    while out.len() < bytes {
        let n = r.gen_range(64..2048).min(bytes - out.len());
        if out.len() > 4096 && r.gen_ratio(1, 2) {
            let start = r.gen_range(0..out.len() - n.min(out.len() - 1));
            let end = (start + n).min(out.len());
            let seg = out[start..end].to_vec();
            out.extend_from_slice(&seg);
        } else if r.gen_ratio(1, 4) {
            out.extend(std::iter::repeat_n(0u8, n));
        } else {
            let mut b = vec![0u8; n];
            r.fill(&mut b[..]);
            out.extend_from_slice(&b);
        }
    }
    out.truncate(bytes);
    out
}

fn put(path: &Path, data: &[u8]) {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).expect("mkdir");
    }
    std::fs::write(path, data).expect("write");
}

fn append(path: &Path, data: &[u8]) {
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).expect("mkdir");
    }
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path).expect("open");
    f.write_all(data).expect("append");
}

/// Sizes, scaled by `scale` (1.0: the defaults the results were taken at).
pub struct Scale(pub f64);

impl Scale {
    fn n(&self, base: usize) -> usize {
        ((base as f64) * self.0).max(1.0) as usize
    }
}

pub fn generate(dataset: &str, dir: &Path, s: &Scale) {
    std::fs::create_dir_all(dir).expect("mkdir");
    match dataset {
        "rust" => gen_rust(dir, s),
        "node" => gen_node(dir, s),
        "home" => gen_home(dir, s),
        "small" => gen_small(dir, s),
        other => panic!("unknown dataset {other}"),
    }
}

/// Applies session `n` (1-based) to `dataset` in `dir`.
pub fn session(dataset: &str, dir: &Path, n: u32, s: &Scale) {
    match dataset {
        "rust" => sess_rust(dir, n, s),
        "node" => sess_node(dir, n, s),
        "home" => sess_home(dir, n, s),
        "small" => sess_small(dir, n, s),
        other => panic!("unknown dataset {other}"),
    }
}

// ---- rust: ~60 MB of sources and lockfile, ~320 MB of target/ at scale 1 ----

fn gen_rust(dir: &Path, s: &Scale) {
    let mut r = rng("rust");
    put(&dir.join("Cargo.toml"), b"[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n");
    put(&dir.join("Cargo.lock"), &text(&mut r, 120_000));
    for i in 0..s.n(400) {
        let size = r.gen_range(2_000..40_000);
        put(&dir.join(format!("src/m{}/f{i}.rs", i % 20)), &text(&mut r, size));
    }
    // target/: rlibs, rmeta, incremental session dirs, build script outputs, one binary.
    for i in 0..s.n(260) {
        let size = r.gen_range(50_000..1_500_000);
        put(&dir.join(format!("target/debug/deps/libcrate{i}-{:08x}.rlib", r.gen::<u32>())), &binary(&mut r, size));
        put(&dir.join(format!("target/debug/deps/libcrate{i}.rmeta")), &binary(&mut r, size / 8));
        put(&dir.join(format!("target/debug/.fingerprint/crate{i}/dep-lib")), &binary(&mut r, 200));
    }
    for i in 0..s.n(60) {
        let size = r.gen_range(5_000..300_000);
        put(&dir.join(format!("target/debug/incremental/demo-{}/s-{i:04}/query-cache.bin", i % 6)), &binary(&mut r, size));
    }
    for i in 0..s.n(40) {
        put(&dir.join(format!("target/debug/build/dep{i}/output")), &text(&mut r, 3_000));
    }
    put(&dir.join("target/debug/demo"), &binary(&mut r, s.n(24_000_000)));
}

fn sess_rust(dir: &Path, n: u32, s: &Scale) {
    let mut r = rng(&format!("rust-session-{n}"));
    for _ in 0..5 {
        let i = r.gen_range(0..s.n(400));
        let p = dir.join(format!("src/m{}/f{i}.rs", i % 20));
        let mut b = std::fs::read(&p).unwrap_or_default();
        let at = r.gen_range(0..b.len().max(1));
        b.splice(at..at, text(&mut r, 400));
        put(&p, &b);
    }
    // A rebuild: the crates touched (and the binary) are rewritten; incremental dirs churn.
    let deps = dir.join("target/debug/deps");
    let mut rlibs: Vec<_> = std::fs::read_dir(&deps).expect("deps").flatten().map(|e| e.path()).collect();
    rlibs.sort();
    for _ in 0..s.n(8) {
        let p = &rlibs[r.gen_range(0..rlibs.len())];
        let size = std::fs::metadata(p).map(|m| m.len() as usize).unwrap_or(100_000);
        put(p, &binary(&mut r, size));
    }
    put(&dir.join("target/debug/demo"), &binary(&mut r, s.n(24_000_000)));
    let inc = dir.join(format!("target/debug/incremental/demo-{}", n % 6));
    let _ = std::fs::remove_dir_all(&inc);
    for i in 0..s.n(10) {
        let size = r.gen_range(5_000..300_000);
        put(&inc.join(format!("s-n{n}-{i:03}/query-cache.bin")), &binary(&mut r, size));
    }
}

// ---- node: ~25k files, ~140 MB at scale 1 ----

fn gen_node(dir: &Path, s: &Scale) {
    let mut r = rng("node");
    put(&dir.join("package.json"), b"{\"name\":\"demo\",\"version\":\"1.0.0\"}\n");
    put(&dir.join("package-lock.json"), &text(&mut r, 400_000));
    for i in 0..s.n(150) {
        let size = r.gen_range(500..12_000);
        put(&dir.join(format!("src/c{}/f{i}.ts", i % 15)), &text(&mut r, size));
    }
    for p in 0..s.n(500) {
        node_package(dir, &mut r, p, 1);
        // One in five packages also appears in a second version, sharing most of its files.
        if p % 5 == 0 {
            node_package(dir, &mut rng(&format!("node-pkg-{p}")), p, 2);
        }
    }
}

fn node_package(dir: &Path, outer: &mut ChaCha8Rng, p: usize, version: u32) {
    let base = if version == 1 { dir.join(format!("node_modules/pkg{p}")) } else { dir.join(format!("node_modules/host{}/node_modules/pkg{p}", p % 17)) };
    let mut r = rng(&format!("node-pkg-{p}"));
    let files = 10 + (r.gen::<u32>() % 80) as usize;
    put(&base.join("package.json"), format!("{{\"name\":\"pkg{p}\",\"version\":\"{version}.0.0\"}}\n").as_bytes());
    for f in 0..files {
        let size = r.gen_range(200..14_000);
        let mut body = text(&mut r, size);
        // The second version changes one file in ten.
        if version == 2 && f % 10 == 0 {
            body = text(outer, size);
        }
        put(&base.join(format!("lib/{}/f{f}.js", f % 6)), &body);
    }
}

fn sess_node(dir: &Path, n: u32, s: &Scale) {
    let mut r = rng(&format!("node-session-{n}"));
    for _ in 0..10 {
        let i = r.gen_range(0..s.n(150));
        let p = dir.join(format!("src/c{}/f{i}.ts", i % 15));
        let mut b = std::fs::read(&p).unwrap_or_default();
        b.extend_from_slice(&text(&mut r, 300));
        put(&p, &b);
    }
    if n % 5 == 0 {
        // An upgrade: one package replaced, one added, one removed; the lockfile changes.
        let p = r.gen_range(0..s.n(500));
        let _ = std::fs::remove_dir_all(dir.join(format!("node_modules/pkg{p}")));
        node_package(dir, &mut r, 100_000 + n as usize, 1);
        let gone = r.gen_range(0..s.n(500));
        let _ = std::fs::remove_dir_all(dir.join(format!("node_modules/pkg{gone}")));
        node_package(dir, &mut rng(&format!("node-up-{n}")), p, 1);
        let lock = dir.join("package-lock.json");
        let mut b = std::fs::read(&lock).unwrap_or_default();
        b.extend_from_slice(&text(&mut r, 2_000));
        put(&lock, &b);
    }
}

// ---- home: Claude Code state, ~45 MB at scale 1 ----

fn jsonl(r: &mut ChaCha8Rng, lines: usize, session: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for i in 0..lines {
        let role = if i % 2 == 0 { "user" } else { "assistant" };
        let n = r.gen_range(200..3_000);
        let body = String::from_utf8(text(r, n)).unwrap_or_default().replace(['"', '\\', '\n'], " ");
        out.extend_from_slice(
            format!(
                "{{\"type\":\"{role}\",\"sessionId\":\"{session}\",\"uuid\":\"{:032x}\",\"timestamp\":\"2026-11-13T00:{:02}:{:02}Z\",\"message\":{{\"role\":\"{role}\",\"content\":\"{body}\"}}}}\n",
                r.gen::<u128>(),
                i / 60 % 60,
                i % 60
            )
            .as_bytes(),
        );
    }
    out
}

fn gen_home(dir: &Path, s: &Scale) {
    let mut r = rng("home");
    for p in 0..3 {
        for k in 0..s.n(8) {
            let sess = format!("{:08x}-{p}-{k}", r.gen::<u32>());
            put(&dir.join(format!(".claude/projects/-workspace-p{p}/{sess}.jsonl")), &jsonl(&mut r, s.n(1_200), &sess));
        }
    }
    for k in 0..s.n(40) {
        put(&dir.join(format!(".claude/todos/t{k}.json")), &text(&mut r, 600));
    }
    put(&dir.join(".claude.json"), &text(&mut r, 20_000));
    put(&dir.join(".bash_history"), &text(&mut r, 80_000));
    for k in 0..s.n(300) {
        let size = r.gen_range(1_000..30_000);
        put(&dir.join(format!(".cache/tool/{}/{k}.bin", k % 10)), &binary(&mut r, size));
    }
}

fn sess_home(dir: &Path, n: u32, s: &Scale) {
    let mut r = rng(&format!("home-session-{n}"));
    let cur = format!("current-{}", n / 5);
    append(&dir.join(format!(".claude/projects/-workspace-p0/{cur}.jsonl")), &jsonl(&mut r, s.n(120), &cur));
    put(&dir.join(format!(".claude/todos/t{}.json", n % 40)), &text(&mut r, 600));
    append(&dir.join(".bash_history"), &text(&mut r, 2_000));
    put(&dir.join(".claude.json"), &text(&mut r, 20_000));
}

// ---- small: ~60k files under 2 KB at scale 1 ----

fn gen_small(dir: &Path, s: &Scale) {
    let mut r = rng("small");
    for i in 0..s.n(60_000) {
        let size = r.gen_range(100..2_000);
        put(&dir.join(format!("d{}/e{}/f{i}.txt", i % 50, (i / 50) % 40)), &text(&mut r, size));
    }
}

fn sess_small(dir: &Path, n: u32, s: &Scale) {
    let mut r = rng(&format!("small-session-{n}"));
    let total = s.n(60_000);
    for _ in 0..total / 100 {
        let i = r.gen_range(0..total);
        let p = dir.join(format!("d{}/e{}/f{i}.txt", i % 50, (i / 50) % 40));
        let size = r.gen_range(100..2_000);
        put(&p, &text(&mut r, size));
    }
    for k in 0..total / 200 {
        let size = r.gen_range(100..2_000);
        put(&dir.join(format!("new/s{n}/f{k}.txt")), &text(&mut r, size));
    }
    for _ in 0..total / 500 {
        let i = r.gen_range(0..total);
        let _ = std::fs::remove_file(dir.join(format!("d{}/e{}/f{i}.txt", i % 50, (i / 50) % 40)));
    }
}
