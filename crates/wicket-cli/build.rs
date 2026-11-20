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
    let static_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/serve/static");
    println!("cargo:rerun-if-env-changed=WICKET_CONSOLE_UNMINIFIED");
    let plain = std::env::var_os("WICKET_CONSOLE_UNMINIFIED").is_some_and(|v| v == "1");
    let read = |rel: &str| {
        let p = static_dir.join(rel);
        println!("cargo:rerun-if-changed={}", p.display());
        (std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())), p)
    };
    let (src, path) = read("console.js");
    let js = if plain { src } else { minify(&src, &path, false) };
    write(&out.join("console.js"), js.as_bytes());
    // The console's ES modules (#574): its own, minified as modules, and lit-html's, copied byte for
    // byte as vendored (static/vendor/lit-html/VENDOR.toml holds their hashes). web.rs serves them
    // under one content-hashed directory, so their relative imports work as written; modules.rs
    // lists them for it, in this order.
    let modules = std::fs::create_dir_all(out.join("modules").join("vendor/lit-html/directives"));
    modules.unwrap_or_else(|e| panic!("{}: {e}", out.display()));
    let mut list = String::from("&[\n");
    for (rel, own) in MODULES {
        let (src, path) = read(rel);
        // The console's own modules import lit-html by its name; vendored files are left as they are.
        let src = if *own { bare_imports(&src, &path, rel) } else { src };
        let js = if *own && !plain { minify(&src, &path, true) } else { src };
        write(&out.join("modules").join(rel), js.as_bytes());
        list.push_str(&format!("    ({rel:?}, include_bytes!(concat!(env!(\"OUT_DIR\"), \"/modules/{rel}\"))),\n"));
    }
    list.push(']');
    write(&out.join("modules.rs"), list.as_bytes());
}

/// The console's modules, relative to static/: the console's own (true: minified), then the
/// vendored lit-html files they import (false: copied as they are).
const MODULES: &[(&str, bool)] = &[
    ("inbox.js", true),
    ("vendor/lit-html/lit-html.js", false),
    ("vendor/lit-html/directive.js", false),
    ("vendor/lit-html/directive-helpers.js", false),
    ("vendor/lit-html/directives/repeat.js", false),
];

/// The console's modules import lit-html by its package name, as `"lit-html"` or
/// `"lit-html/directives/repeat.js"` (#574); this rewrites each to the vendored file, relative to the
/// module (`./vendor/lit-html/…`), so the browser needs no import map and the CSP stays
/// `script-src 'self'`. A relative import is left as it is; any other bare name fails the build.
fn bare_imports(src: &str, path: &Path, rel: &str) -> String {
    use oxc_allocator::Allocator;
    use oxc_ast::ast::Statement;
    use oxc_parser::Parser;
    use oxc_span::SourceType;
    let alloc = Allocator::default();
    let parsed = Parser::new(&alloc, src, SourceType::mjs()).parse();
    if !parsed.diagnostics.is_empty() {
        panic!("{}: {:?}", path.display(), parsed.diagnostics);
    }
    // From the module to the modules' root: "./" at the root, "../" for each directory below it.
    let up = match rel.matches('/').count() {
        0 => "./".to_string(),
        n => "../".repeat(n),
    };
    let mut edits = vec![];
    for st in &parsed.program.body {
        let source = match st {
            Statement::ImportDeclaration(d) => &d.source,
            Statement::ExportAllDeclaration(d) => &d.source,
            _ => continue,
        };
        let Some(spec) = source.value.as_str() else { panic!("{}: an import path that isn't plain text", path.display()) };
        let to = if spec.starts_with("./") || spec.starts_with("../") {
            continue;
        } else if spec == "lit-html" {
            format!("{up}vendor/lit-html/lit-html.js")
        } else if let Some(sub) = spec.strip_prefix("lit-html/") {
            format!("{up}vendor/lit-html/{sub}")
        } else {
            panic!("{}: import from {spec:?}: only lit-html (vendored) or a relative path", path.display());
        };
        edits.push((source.span.start as usize, source.span.end as usize, format!("{to:?}")));
    }
    let mut out = src.to_string();
    for (start, end, to) in edits.into_iter().rev() {
        out.replace_range(start..end, &to);
    }
    out
}

fn minify(src: &str, path: &Path, module: bool) -> String {
    use oxc_allocator::Allocator;
    use oxc_codegen::{Codegen, CodegenOptions};
    use oxc_minifier::{CompressOptions, MangleOptions, Minifier, MinifierOptions};
    use oxc_parser::Parser;
    use oxc_span::SourceType;
    let alloc = Allocator::default();
    let parsed = Parser::new(&alloc, src, if module { SourceType::mjs() } else { SourceType::script() }).parse();
    if !parsed.diagnostics.is_empty() {
        panic!("{}: {:?}", path.display(), parsed.diagnostics);
    }
    let mut program = parsed.program;
    let opts = MinifierOptions {
        // A module's top level is its own, so its names are shortened too (its exports keep theirs).
        mangle: Some(MangleOptions { top_level: Some(module), ..MangleOptions::default() }),
        mangle_properties: None,
        compress: Some(CompressOptions::default()),
    };
    let min = Minifier::new(opts).minify(&alloc, &mut program);
    Codegen::new().with_options(CodegenOptions::minify()).with_scoping(min.scoping).build(&program).code
}
