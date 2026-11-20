//! The console's static files and the security headers on every response.
//!
//! The page has no inline script or style: its script and stylesheet are separate files served
//! under paths that carry their content hash (and with Subresource Integrity on the page), so the
//! Content-Security-Policy can be `script-src 'self'` with nothing inline, and the files can be cached
//! forever. The static files are the same for everyone and carry no data; they are the only things
//! (with the sign-in endpoints) an unauthenticated client can fetch.

use base64::Engine;
use bytes::Bytes;
use http::header::{HeaderMap, HeaderValue};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::LazyLock;

/// The policy on every response. Nothing inline, nothing from elsewhere, no framing, no `<base>`;
/// `manifest-src` lets the browser read the web app manifest (with `default-src 'none'` it couldn't).
pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; \
manifest-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// Trusted Types, reported but not yet enforced (#739): the console's DOM writes must go through text
/// or lit-html's templates, never a raw HTML or script sink. Browsers that support it report a write
/// that would break that (in the console and as a `securitypolicyviolation` event, which the browser
/// tests fail on); it moves into [`CSP`] once every screen is on Lit.
pub const CSP_REPORT_ONLY: &str = "require-trusted-types-for 'script'; trusted-types lit-html";

/// Strict-Transport-Security for HTTPS origins: two years, subdomains, and eligible for the browsers'
/// preload lists (submitting the domain to hstspreload.org is the operator's step).
pub const HSTS: &str = "max-age=63072000; includeSubDomains; preload";

pub struct Asset {
    pub ctype: &'static str,
    pub body: Bytes,
    /// Named by content hash: cacheable forever.
    pub immutable: bool,
}

pub struct Assets {
    pub page: Bytes,
    /// A run's session page (#327), `/session?run=<id>`: the same for every run (the page reads the
    /// run from its URL), and like the console's page, no data in it.
    pub session_page: Bytes,
    pub files: HashMap<String, Asset>,
}

/// The session view's bundle (web/session, #327), as `build.rs` embedded it: built in CI, or a
/// placeholder page when the build had no bundle.
pub const SESSION_JS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/session.js"));
pub const SESSION_CSS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/session.css"));
/// Whether [`SESSION_JS`] is the real view (false: the placeholder).
pub const SESSION_VIEW_BUILT: bool = matches!(env!("WICKET_SESSION_VIEW_BUILT").as_bytes(), b"1");

fn hashed(name: &str, ext: &str, body: &[u8]) -> (String, String) {
    let digest = sha2::Sha256::digest(body);
    let path = format!("/static/{name}.{}.{ext}", &hex::encode(digest)[..16]);
    let sri = format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(digest));
    (path, sri)
}

/// The console's script as served: static/console.js, minified by build.rs (#574).
const CONSOLE_JS: &str = include_str!(concat!(env!("OUT_DIR"), "/console.js"));

/// The console's script as served (for the tests that run it).
#[cfg(test)]
pub fn console_js() -> &'static str {
    CONSOLE_JS
}

/// The console's ES modules (#574), as build.rs wrote them: (path under the module directory, bytes),
/// its own first (`inbox.js`, the entry), then the vendored lit-html files they import.
const MODULES: &[(&str, &[u8])] = include!(concat!(env!("OUT_DIR"), "/modules.rs"));

/// The console's modules' directory, `/static/m.<hash>/`, named by a hash over every module's path and
/// bytes, so their relative imports resolve as written and any change gives a new directory; and the
/// page's tags for them: a `modulepreload` with Subresource Integrity for each import, then the entry.
fn modules() -> (String, String) {
    let mut h = sha2::Sha256::new();
    for (path, body) in MODULES {
        h.update((path.len() as u64).to_le_bytes());
        h.update(path.as_bytes());
        h.update((body.len() as u64).to_le_bytes());
        h.update(body);
    }
    let dir = format!("/static/m.{}", &hex::encode(h.finalize())[..16]);
    let sri = |b: &[u8]| format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(b)));
    let mut tags = String::new();
    for (path, body) in &MODULES[1..] {
        tags.push_str(&format!("<link rel=\"modulepreload\" href=\"{dir}/{path}\" integrity=\"{}\">\n", sri(body)));
    }
    let (entry, body) = MODULES[0];
    tags.push_str(&format!("<script type=\"module\" src=\"{dir}/{entry}\" integrity=\"{}\"></script>", sri(body)));
    (dir, tags)
}

pub static ASSETS: LazyLock<Assets> = LazyLock::new(|| {
    const JS: &str = CONSOLE_JS;
    let (module_dir, module_tags) = modules();
    const CSS: &str = include_str!("static/console.css");
    let (js, js_sri) = hashed("console", "js", JS.as_bytes());
    let (css, css_sri) = hashed("console", "css", CSS.as_bytes());
    let page = include_str!("static/console.html")
        .replace("{{css}}", &css)
        .replace("{{css_sri}}", &css_sri)
        .replace("{{js}}", &js)
        .replace("{{js_sri}}", &js_sri)
        .replace("{{modules}}", &module_tags);
    let (sjs, sjs_sri) = hashed("session", "js", SESSION_JS);
    let (scss, scss_sri) = hashed("session", "css", SESSION_CSS);
    let session_page = include_str!("static/session.html")
        .replace("{{css}}", &scss)
        .replace("{{css_sri}}", &scss_sri)
        .replace("{{js}}", &sjs)
        .replace("{{js_sri}}", &sjs_sri);
    let mut files = HashMap::new();
    let mut add = |path: &str, ctype: &'static str, body: &'static [u8], immutable: bool| {
        files.insert(path.to_string(), Asset { ctype, body: Bytes::from_static(body), immutable });
    };
    add(&js, "text/javascript; charset=utf-8", JS.as_bytes(), true);
    for (path, body) in MODULES {
        add(&format!("{module_dir}/{path}"), "text/javascript; charset=utf-8", body, true);
    }
    add(&css, "text/css; charset=utf-8", CSS.as_bytes(), true);
    add(&sjs, "text/javascript; charset=utf-8", SESSION_JS, true);
    add(&scss, "text/css; charset=utf-8", SESSION_CSS, true);
    // The service worker (Web Push): at the root so its scope is the whole console, and not cached
    // for long so a new build's reaches devices. The CSP's `script-src 'self'` allows it (with no
    // `worker-src`, workers fall back to `script-src`).
    add("/sw.js", "text/javascript; charset=utf-8", include_bytes!("static/sw.js"), false);
    add("/manifest.webmanifest", "application/manifest+json", include_bytes!("static/manifest.webmanifest"), false);
    add("/static/icon.svg", "image/svg+xml", include_bytes!("static/icon.svg"), false);
    add("/static/icon-192.png", "image/png", include_bytes!("static/icon-192.png"), false);
    add("/static/icon-512.png", "image/png", include_bytes!("static/icon-512.png"), false);
    add("/static/apple-touch-icon.png", "image/png", include_bytes!("static/apple-touch-icon.png"), false);
    Assets { page: Bytes::from(page), session_page: Bytes::from(session_page), files }
});

/// Sets the security headers every response carries (replacing any a handler set), and HSTS when
/// the console's origin is HTTPS. No CORS headers, ever: the console is same-origin only.
pub fn secure_headers(h: &mut HeaderMap, hsts: bool) {
    let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(h, "content-security-policy", CSP);
    set(h, "content-security-policy-report-only", CSP_REPORT_ONLY);
    set(h, "x-content-type-options", "nosniff");
    set(h, "referrer-policy", "no-referrer");
    set(h, "x-frame-options", "DENY");
    set(h, "cross-origin-opener-policy", "same-origin");
    set(h, "cross-origin-resource-policy", "same-origin");
    set(
        h,
        "permissions-policy",
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
    );
    if !h.contains_key("cache-control") {
        set(h, "cache-control", "no-store");
    }
    if hsts {
        set(h, "strict-transport-security", HSTS);
    }
    for k in ["access-control-allow-origin", "access-control-allow-credentials", "server", "x-powered-by"] {
        h.remove(k);
    }
}

/// Writes the console as `wicket serve` sends it into `dir` (#574): `index.html` (the page), each
/// file at its served path (`static/console.<hash>.js`, `sw.js`, …), and `headers.json` with the
/// security headers, for the browser tests (ci/console-browsers.sh) to serve the same bytes under the
/// same policy without a ledger.
pub fn write_console_assets(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("index.html"), &ASSETS.page)?;
    for (path, a) in &ASSETS.files {
        let p = dir.join(path.trim_start_matches('/'));
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(p, &a.body)?;
    }
    let headers = serde_json::json!({ "content-security-policy": CSP, "content-security-policy-report-only": CSP_REPORT_ONLY });
    std::fs::write(dir.join("headers.json"), serde_json::to_vec_pretty(&headers)?)
}
