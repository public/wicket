//! Embeds the console's session view (#327): the bundle `web/session` builds (`npm ci`, `npm run
//! build`; CI does it, `ci/session-view.sh`), from the directory `WICKET_SESSION_VIEW` names
//! (absolute, or relative to the workspace root). It holds `session.js` and `session.css`, and
//! nothing about the build machine: the same lockfile gives the same bytes. Without it, a build
//! embeds a placeholder that says the view wasn't built, so `cargo build` needs no Node.
//!
//! Reproducible (#190): only the two files' bytes go in, copied to `OUT_DIR` under fixed names; no
//! paths, times or environment.

use std::path::{Path, PathBuf};

const PLACEHOLDER_JS: &str = "\"use strict\";\n\
// This wicket was built without its session view (WICKET_SESSION_VIEW unset at build time).\n\
document.getElementById(\"app\").textContent = \"This build of wicket has no session view: it was built without the web/session bundle \
(see docs/reference/console.md). The console's other pages work as usual.\";\n";
const PLACEHOLDER_CSS: &str =
    "/* This wicket was built without its session view. */\nbody { font: 15px/1.5 system-ui, sans-serif; margin: 24px; }\n";

fn main() {
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
