//! Embeds the console's session view (#327): the bundle `web/session` builds (`npm ci`, `npm run
//! build`; CI does it, `ci/session-view.sh`), from the directory `WICKET_SESSION_VIEW` names
//! (absolute, or relative to the workspace root). It holds `session.js` and `session.css`, and
//! nothing about the build machine: the same lockfile gives the same bytes. Without it, a build
//! embeds a placeholder that says the view wasn't built, so `cargo build` needs no Node.
//!
//! Reproducible (#190): only the two files' bytes go in, copied to `OUT_DIR` under fixed names; no
//! paths, times or environment.
//!
//! It also minifies the console's own script (`src/serve/static/console.js`, #574) with Oxc, from
//! crates Cargo fetched, so the page downloads less and `cargo build` still needs nothing else. Local
//! names are shortened; top-level names are kept (the console is a classic script, and its tests call
//! them). The output depends only on the source and the pinned Oxc. `WICKET_CONSOLE_UNMINIFIED=1`
//! embeds the source as written, for reading it in a browser's debugger.

use std::path::{Path, PathBuf};

const PLACEHOLDER_JS: &str = "\"use strict\";\n\
// This wicket was built without its session view (WICKET_SESSION_VIEW unset at build time).\n\
document.getElementById(\"app\").textContent = \"This build of wicket has no session view: it was built without the web/session bundle \
(see docs/reference/console.md). The console's other pages work as usual.\";\n";
const PLACEHOLDER_CSS: &str =
    "/* This wicket was built without its session view. */\nbody { font: 15px/1.5 system-ui, sans-serif; margin: 24px; }\n";

fn main() {
    console(&PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR")));
    println!("cargo:rerun-if-env-changed=WICKET_SESSION_VIEW");
    println!("cargo:rerun-if-changed=build.rs");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let (js, css, built) = match std::env::var_os("WICKET_SESSION_VIEW").filter(|d| !d.is_empty()) {
        Some(d) => {
            let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            let dir = root.join(d);
            let read = |f: &str| {
                let p = dir.join(f);
                println!("cargo:rerun-if-changed={}", p.display());
                std::fs::read(&p)
                    .unwrap_or_else(|e| panic!("WICKET_SESSION_VIEW: {}: {e} (build web/session first: ci/session-view.sh)", p.display()))
            };
            (read("session.js"), read("session.css"), true)
        }
        None => (PLACEHOLDER_JS.as_bytes().to_vec(), PLACEHOLDER_CSS.as_bytes().to_vec(), false),
    };
    write(&out.join("session.js"), &js);
    write(&out.join("session.css"), &css);
    println!("cargo:rustc-env=WICKET_SESSION_VIEW_BUILT={}", if built { "1" } else { "0" });
}

/// Writes only when the bytes differ, so an unchanged bundle doesn't rebuild the crate.
fn write(p: &Path, b: &[u8]) {
    if std::fs::read(p).ok().as_deref() != Some(b) {
        std::fs::write(p, b).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    }
}

/// The console's script, minified into `OUT_DIR/console.js` (or copied as written, with
/// `WICKET_CONSOLE_UNMINIFIED=1`). A parse error fails the build: the page would not run.
fn console(out: &Path) {
    let src_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/serve/static/console.js");
    println!("cargo:rerun-if-changed={}", src_path.display());
    println!("cargo:rerun-if-env-changed=WICKET_CONSOLE_UNMINIFIED");
    let src = std::fs::read_to_string(&src_path).unwrap_or_else(|e| panic!("{}: {e}", src_path.display()));
    let js = if std::env::var_os("WICKET_CONSOLE_UNMINIFIED").is_some_and(|v| v == "1") { src } else { minify(&src, &src_path) };
    write(&out.join("console.js"), js.as_bytes());
}

fn minify(src: &str, path: &Path) -> String {
    use oxc_allocator::Allocator;
    use oxc_codegen::{Codegen, CodegenOptions};
    use oxc_minifier::{CompressOptions, MangleOptions, Minifier, MinifierOptions};
    use oxc_parser::Parser;
    use oxc_span::SourceType;
    let alloc = Allocator::default();
    let parsed = Parser::new(&alloc, src, SourceType::script()).parse();
    if !parsed.diagnostics.is_empty() {
        panic!("{}", report(path, src, &parsed.diagnostics));
    }
    let mut program = parsed.program;
    let opts = MinifierOptions {
        mangle: Some(MangleOptions { top_level: Some(false), ..MangleOptions::default() }),
        mangle_properties: None,
        compress: Some(CompressOptions::default()),
    };
    let min = Minifier::new(opts).minify(&alloc, &mut program);
    Codegen::new().with_options(CodegenOptions::minify()).with_scoping(min.scoping).build(&program).code
}

/// A parse error as `file:line:column: message`, with the line itself, one per error: the console's
/// script doesn't parse, so the page wouldn't run, and the build stops saying where.
fn report(path: &Path, src: &str, diags: &[oxc_diagnostics::OxcDiagnostic]) -> String {
    let mut out = format!("the console's JavaScript doesn't parse ({} error(s)):", diags.len());
    for d in diags {
        let at = (d.labels.first().map_or(0, |l| l.offset() as usize)).min(src.len());
        let line_start = src[..at].rfind('\n').map_or(0, |i| i + 1);
        let line_no = src[..at].matches('\n').count() + 1;
        let col = src[line_start..at].chars().count() + 1;
        let text = src[line_start..].lines().next().unwrap_or("");
        out.push_str(&format!("\n  {}:{line_no}:{col}: {}\n    {}", path.display(), d.message, text.trim_end()));
    }
    out
}
