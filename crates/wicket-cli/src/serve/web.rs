//! The console's static files and the security headers on every response.
//!
//! The page has no inline script or style: its script and stylesheet are separate files served
//! under paths that carry their content hash (and with Subresource Integrity on the page), so the
//! Content-Security-Policy can be `script-src 'self'` with nothing inline, and the files can be cached
//! forever. The static files are the same for everyone and carry no data; they are the only things
//! (with the sign-in endpoints) an unauthenticated client can fetch.

use bytes::Bytes;
use http::header::{HeaderMap, HeaderValue};
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
    /// The same bytes, Brotli-compressed at build time (#574), for a browser that accepts `br`; `None`
    /// for a file it doesn't make smaller (a PNG).
    pub br: Option<Bytes>,
    /// Named by content hash: cacheable forever.
    pub immutable: bool,
}

impl Asset {
    /// The bytes to send for a request with this `Accept-Encoding`, and the `Content-Encoding` they
    /// carry: the Brotli copy when the browser accepts `br`, else the original.
    pub fn for_encoding(&self, accept: Option<&str>) -> (Bytes, Option<&'static str>) {
        match &self.br {
            Some(br) if accepts(accept, "br") => (br.clone(), Some("br")),
            _ => (self.body.clone(), None),
        }
    }
}

/// Whether an `Accept-Encoding` value accepts `coding`: named, or `*`, with a q-value above 0.
pub fn accepts(accept: Option<&str>, coding: &str) -> bool {
    let mut named = None;
    let mut star = None;
    for item in accept.unwrap_or("").split(',') {
        let mut parts = item.split(';');
        let name = parts.next().unwrap_or("").trim();
        let q = parts
            .filter_map(|p| p.trim().strip_prefix("q=").or_else(|| p.trim().strip_prefix("Q=")))
            .next()
            .and_then(|q| q.trim().parse::<f32>().ok())
            .unwrap_or(1.0);
        if name.eq_ignore_ascii_case(coding) {
            named = Some(q > 0.0);
        } else if name == "*" {
            star = Some(q > 0.0);
        }
    }
    named.or(star).unwrap_or(false)
}

pub struct Assets {
    pub page: Asset,
    /// A run's session page (#327), `/session?run=<id>`: the same for every run (the page reads the
    /// run from its URL), and like the console's page, no data in it.
    pub session_page: Asset,
    pub files: HashMap<String, Asset>,
}

/// Whether the session view's bundle (web/session, #327) was in this build (false: build.rs embedded
/// a placeholder page saying it wasn't).
pub const SESSION_VIEW_BUILT: bool = matches!(env!("WICKET_SESSION_VIEW_BUILT").as_bytes(), b"1");

/// The console's script as build.rs minified it (#574), from static/console.js, for the tests that
/// run it.
#[cfg(test)]
pub fn console_js() -> &'static str {
    include_str!(concat!(env!("OUT_DIR"), "/console.js"))
}

/// Everything wicket serves from its own bytes, as build.rs made it (#574): (path, content type,
/// cacheable for good, bytes, Brotli copy). Files under `/static/` are named by their content's hash;
/// the pages and `/sw.js` keep fixed names; the pages' references to the others are filled in.
/// One file as build.rs wrote it: its path, content type, whether it is immutable, the bytes, and
/// their Brotli copy (none when it wasn't smaller).
type Built = (&'static str, &'static str, bool, &'static [u8], Option<&'static [u8]>);
const BUILT: &[Built] = include!(concat!(env!("OUT_DIR"), "/assets.rs"));

pub static ASSETS: LazyLock<Assets> = LazyLock::new(|| {
    let mut files: HashMap<String, Asset> = BUILT
        .iter()
        .map(|&(path, ctype, immutable, body, br)| {
            let ctype: &'static str = ctype;
            (path.to_string(), Asset { ctype, body: Bytes::from_static(body), br: br.map(Bytes::from_static), immutable })
        })
        .collect();
    let page = files.remove("/").expect("build.rs writes the page");
    let session_page = files.remove("/session").expect("build.rs writes the session page");
    Assets { page, session_page, files }
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
/// file at its served path (`static/console.<hash>.js`, `sw.js`, …) with its Brotli copy as
/// `<file>.br` where there is one, and `headers.json` with the
/// security headers, for the browser tests (ci/console-browsers.sh) to serve the same bytes under the
/// same policy without a ledger.
pub fn write_console_assets(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("index.html"), &ASSETS.page.body)?;
    if let Some(br) = &ASSETS.page.br {
        std::fs::write(dir.join("index.html.br"), br)?;
    }
    for (path, a) in &ASSETS.files {
        let p = dir.join(path.trim_start_matches('/'));
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&p, &a.body)?;
        // Its Brotli copy beside it, as `<file>.br`, for a server of the dump to send as wicket does.
        if let Some(br) = &a.br {
            std::fs::write(p.with_file_name(format!("{}.br", p.file_name().and_then(|n| n.to_str()).unwrap_or_default())), br)?;
        }
    }
    let headers = serde_json::json!({ "content-security-policy": CSP, "content-security-policy-report-only": CSP_REPORT_ONLY });
    std::fs::write(dir.join("headers.json"), serde_json::to_vec_pretty(&headers)?)
}
