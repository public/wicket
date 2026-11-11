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
    pub files: HashMap<String, Asset>,
}

fn hashed(name: &str, ext: &str, body: &[u8]) -> (String, String) {
    let digest = sha2::Sha256::digest(body);
    let path = format!("/static/{name}.{}.{ext}", &hex::encode(digest)[..16]);
    let sri = format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(digest));
    (path, sri)
}

pub static ASSETS: LazyLock<Assets> = LazyLock::new(|| {
    const JS: &str = include_str!("static/console.js");
    const CSS: &str = include_str!("static/console.css");
    let (js, js_sri) = hashed("console", "js", JS.as_bytes());
    let (css, css_sri) = hashed("console", "css", CSS.as_bytes());
    let page = include_str!("static/console.html")
        .replace("{{css}}", &css)
        .replace("{{css_sri}}", &css_sri)
        .replace("{{js}}", &js)
        .replace("{{js_sri}}", &js_sri);
    let mut files = HashMap::new();
    let mut add = |path: &str, ctype: &'static str, body: &'static [u8], immutable: bool| {
        files.insert(path.to_string(), Asset { ctype, body: Bytes::from_static(body), immutable });
    };
    add(&js, "text/javascript; charset=utf-8", JS.as_bytes(), true);
    add(&css, "text/css; charset=utf-8", CSS.as_bytes(), true);
    add("/manifest.webmanifest", "application/manifest+json", include_bytes!("static/manifest.webmanifest"), false);
    add("/static/icon.svg", "image/svg+xml", include_bytes!("static/icon.svg"), false);
    add("/static/icon-192.png", "image/png", include_bytes!("static/icon-192.png"), false);
    add("/static/icon-512.png", "image/png", include_bytes!("static/icon-512.png"), false);
    add("/static/apple-touch-icon.png", "image/png", include_bytes!("static/apple-touch-icon.png"), false);
    Assets { page: Bytes::from(page), files }
});

/// Sets the security headers every response carries (replacing any a handler set), and HSTS when
/// the console's origin is HTTPS. No CORS headers, ever: the console is same-origin only.
pub fn secure_headers(h: &mut HeaderMap, hsts: bool) {
    let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(h, "content-security-policy", CSP);
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
