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
    assets(&out);
}

/// Every file `wicket serve` sends from its own bytes (#574), as it sends them, into `assets.rs` for
/// web.rs: each with its path, content type, whether it may be cached for good, its bytes and, for a
/// file a Brotli copy is smaller for, that copy.
///
/// - **Named by content hash:** every file under `/static/` (`console.<hash>.js`, `icon-192.<hash>.png`,
///   `manifest.<hash>.webmanifest`, and the modules' `/static/m.<hash>/` directory), so a browser may
///   keep it forever and a new build's is a new name. The pages (`/`, `/session`) and the service
///   worker (`/sw.js`) keep fixed names: a browser asks for them by that name, and checks the service
///   worker there for a new build.
/// - **References filled in:** the pages' `{{…}}` placeholders (each file's path, with Subresource
///   Integrity for scripts and styles), and the hashed icons' paths in the manifest and the service
///   worker.
/// - **Brotli**, quality 11 and the largest window (24), the most it compresses: done once, here, so
///   serving costs nothing. All three target browsers accept `br` over HTTPS; the original is sent to
///   one that doesn't say it does. Deterministic: the same files give the same bytes.
fn assets(out: &Path) {
    use base64::Engine;
    use sha2::Digest;
    let st = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/serve/static");
    let src = |rel: &str| -> Vec<u8> {
        let p = st.join(rel);
        println!("cargo:rerun-if-changed={}", p.display());
        std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    };
    let built = |rel: &str| -> Vec<u8> { std::fs::read(out.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}")) };
    let digest = |b: &[u8]| sha2::Sha256::digest(b);
    let named = |stem: &str, ext: &str, b: &[u8]| format!("/static/{stem}.{}.{ext}", &hex::encode(digest(b))[..16]);
    let sri = |b: &[u8]| format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(digest(b)));
    // (path, content type, immutable, bytes)
    let mut files: Vec<(String, &'static str, bool, Vec<u8>)> = vec![];
    const JS: &str = "text/javascript; charset=utf-8";
    const CSS: &str = "text/css; charset=utf-8";

    // Icons, then what names them.
    let mut icons = vec![];
    for (rel, stem, ext, ctype) in [
        ("icon.svg", "icon", "svg", "image/svg+xml"),
        ("icon-192.png", "icon-192", "png", "image/png"),
        ("icon-512.png", "icon-512", "png", "image/png"),
        ("apple-touch-icon.png", "apple-touch-icon", "png", "image/png"),
    ] {
        let b = src(rel);
        let path = named(stem, ext, &b);
        icons.push((format!("/static/{rel}"), path.clone()));
        files.push((path, ctype, true, b));
    }
    // Each icon's path, quoted (double or single), becomes its hashed one in the manifest and the
    // service worker; one left unswapped would be a 404 (the test checks sw.js).
    let with_icons = |text: String| {
        icons.iter().fold(text, |t, (from, to)| {
            t.replace(&format!("\"{from}\""), &format!("\"{to}\"")).replace(&format!("'{from}'"), &format!("'{to}'"))
        })
    };
    let manifest = with_icons(String::from_utf8(src("manifest.webmanifest")).expect("utf-8")).into_bytes();
    let manifest_path = named("manifest", "webmanifest", &manifest);
    files.push((manifest_path.clone(), "application/manifest+json", true, manifest));
    // The service worker (Web Push): at the root so its scope is the whole console, and asked for
    // anew (`no-cache`) so a new build's reaches devices. The CSP's `script-src 'self'` allows it.
    files.push(("/sw.js".into(), JS, false, with_icons(String::from_utf8(src("sw.js")).expect("utf-8")).into_bytes()));

    // The console's script and style, and its modules' directory.
    let js = built("console.js");
    let css = src("console.css");
    let (js_path, js_sri, css_path, css_sri) = (named("console", "js", &js), sri(&js), named("console", "css", &css), sri(&css));
    let modules: Vec<(&str, Vec<u8>)> = MODULES.iter().map(|(rel, _)| (*rel, built(&format!("modules/{rel}")))).collect();
    let mut h = sha2::Sha256::new();
    for (rel, b) in &modules {
        h.update((rel.len() as u64).to_le_bytes());
        h.update(rel.as_bytes());
        h.update((b.len() as u64).to_le_bytes());
        h.update(b);
    }
    let dir = format!("/static/m.{}", &hex::encode(h.finalize())[..16]);
    // What the views import (the console's shared module and lit-html's files) preloaded, with their
    // hashes, so the imports are checked too; then each view as a script of its own.
    let mut module_tags = String::new();
    for ((rel, b), _) in modules.iter().zip(MODULES).filter(|(_, (_, kind))| !matches!(kind, Module::View)) {
        module_tags.push_str(&format!("<link rel=\"modulepreload\" href=\"{dir}/{rel}\" integrity=\"{}\">\n", sri(b)));
    }
    let views: Vec<String> = modules
        .iter()
        .zip(MODULES)
        .filter(|(_, (_, kind))| matches!(kind, Module::View))
        .map(|((rel, b), _)| format!("<script type=\"module\" src=\"{dir}/{rel}\" integrity=\"{}\"></script>", sri(b)))
        .collect();
    module_tags.push_str(&views.join("\n"));
    let (sjs, scss) = (built("session.js"), built("session.css"));
    let (sjs_path, sjs_sri, scss_path, scss_sri) = (named("session", "js", &sjs), sri(&sjs), named("session", "css", &scss), sri(&scss));
    let icon_of = |rel: &str| icons.iter().find(|(from, _)| from == &format!("/static/{rel}")).map(|(_, to)| to.clone()).expect("an icon");
    let page = |tpl: &str, js: &str, js_sri: &str, css: &str, css_sri: &str, modules: &str| -> Vec<u8> {
        let mut p = String::from_utf8(src(tpl)).expect("utf-8");
        for (k, v) in [
            ("{{js}}", js),
            ("{{js_sri}}", js_sri),
            ("{{css}}", css),
            ("{{css_sri}}", css_sri),
            ("{{modules}}", modules),
            ("{{manifest}}", manifest_path.as_str()),
            ("{{icon_svg}}", icon_of("icon.svg").as_str()),
            ("{{apple_touch_icon}}", icon_of("apple-touch-icon.png").as_str()),
        ] {
            p = p.replace(k, v);
        }
        assert!(!p.contains("{{"), "{tpl}: a placeholder with no value");
        p.into_bytes()
    };
    files.push(("/".into(), "text/html; charset=utf-8", false, page("console.html", &js_path, &js_sri, &css_path, &css_sri, &module_tags)));
    files.push((
        "/session".into(),
        "text/html; charset=utf-8",
        false,
        page("session.html", &sjs_path, &sjs_sri, &scss_path, &scss_sri, ""),
    ));
    files.push((js_path, JS, true, js));
    files.push((css_path, CSS, true, css));
    files.push((sjs_path, JS, true, sjs));
    files.push((scss_path, CSS, true, scss));
    for (rel, b) in modules {
        files.push((format!("{dir}/{rel}"), JS, true, b));
    }

    // Each file's bytes, and its Brotli copy where that is smaller, into OUT_DIR/assets/.
    let mut list = String::from("&[\n");
    for (i, (path, ctype, immutable, body)) in files.iter().enumerate() {
        let dest = out.join("assets").join(i.to_string());
        std::fs::create_dir_all(out.join("assets")).unwrap_or_else(|e| panic!("{}: {e}", out.display()));
        write(&dest, body);
        // Every file, images too: the icons are small PNGs a copy is half the size of.
        let mut br = Vec::new();
        {
            use std::io::Write;
            let mut w = brotli::CompressorWriter::new(&mut br, 4096, 11, 24);
            w.write_all(body).unwrap_or_else(|e| panic!("brotli {path}: {e}"));
        }
        let br_expr = if br.len() < body.len() {
            write(&out.join("assets").join(format!("{i}.br")), &br);
            format!("Some(include_bytes!(concat!(env!(\"OUT_DIR\"), \"/assets/{i}.br\")))")
        } else {
            "None".into()
        };
        list.push_str(&format!(
            "    ({path:?}, {ctype:?}, {immutable}, include_bytes!(concat!(env!(\"OUT_DIR\"), \"/assets/{i}\")), {br_expr}),\n"
        ));
    }
    list.push(']');
    write(&out.join("assets.rs"), list.as_bytes());
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
    // byte as vendored (static/vendor/lit-html/VENDOR.toml holds their hashes). `assets` serves them
    // under one content-hashed directory, so their relative imports work as written.
    let modules = std::fs::create_dir_all(out.join("modules").join("vendor/lit-html/directives"));
    modules.unwrap_or_else(|e| panic!("{}: {e}", out.display()));
    for (rel, kind) in MODULES {
        let own = !matches!(kind, Module::Vendored);
        let (src, path) = read(rel);
        // The console's own modules import lit-html by its name; vendored files are left as they are.
        let src = if own { bare_imports(&src, &path, rel) } else { src };
        let js = if own && !plain { minify(&src, &path, true) } else { src };
        write(&out.join("modules").join(rel), js.as_bytes());
    }
}

/// What a console module is: a view the page loads, shared code the views import (both the
/// console's own, minified), or a vendored lit-html file (copied as it is).
enum Module {
    View,
    Shared,
    Vendored,
}

/// The console's modules, relative to static/.
const MODULES: &[(&str, Module)] = &[
    ("inbox.js", Module::View),
    ("agents.js", Module::View),
    ("activity.js", Module::View),
    ("settings.js", Module::View),
    ("ui.js", Module::Shared),
    ("vendor/lit-html/lit-html.js", Module::Vendored),
    ("vendor/lit-html/directive.js", Module::Vendored),
    ("vendor/lit-html/directive-helpers.js", Module::Vendored),
    ("vendor/lit-html/directives/repeat.js", Module::Vendored),
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
        panic!("{}", report(path, src, &parsed.diagnostics));
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
        let file = if spec.starts_with("./") || spec.starts_with("../") {
            continue;
        } else if spec == "lit-html" {
            "lit-html.js"
        } else if let Some(sub) = spec.strip_prefix("lit-html/") {
            sub
        } else {
            panic!("{}: import from {spec:?}: only lit-html (vendored) or a relative path", path.display());
        };
        // Only a file that is vendored and served (MODULES), so an import can't name one that isn't.
        let vendored = format!("vendor/lit-html/{file}");
        if !MODULES.iter().any(|(rel, kind)| matches!(kind, Module::Vendored) && *rel == vendored) {
            panic!(
                "{}: import from {spec:?}: static/{vendored} isn't among the vendored modules build.rs serves (MODULES)",
                path.display()
            );
        }
        let to = format!("{up}{vendored}");
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
        panic!("{}", report(path, src, &parsed.diagnostics));
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
