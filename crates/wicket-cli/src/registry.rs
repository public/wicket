//! Pulling an image by digest from a registry, host-side on a node (#191): the [OCI distribution
//! API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md), by digest only,
//! from an allowlisted registry, never from inside a box.
//!
//! - **Only the hosts it was given.** The registry's own host, its token service's (`auth_hosts`)
//!   and where it redirects blob downloads (`blob_hosts`); anything else, a redirect included, is
//!   refused. HTTPS only, except for a registry on a loopback address.
//! - **By digest.** The manifest is fetched as `manifests/<pin>` and must hash to the pin; every
//!   blob is hashed as it is written and must match its descriptor's digest and size. From an index,
//!   only this node's platform is fetched.
//! - **Then as any delivered image:** [`crate::oci::finish`] checks the image is whole and writes the
//!   layout the node's runtime imports, naming the pin alone.
//! - **Credentials** (a vault secret, fetched by the node for the run like any other, #152):
//!   `user:password` (HTTP Basic, to the registry or its token service) or a bearer token. Never
//!   written to disk or logged.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

/// Where a node may pull an image from (#191): what [`crate::images_policy::Registry`] allows, as
/// the control host sends it with a pull.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    /// The registry's host (`host[:port]`).
    pub host: String,
    /// The repository there (`team/agent`).
    pub repository: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blob_hosts: Vec<String>,
    /// The vault secret the node fetches for it, if it needs one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

fn loopback(host: &str) -> bool {
    let h = host.rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map_or(host, |(h, _)| h);
    let h = h.trim_start_matches('[').trim_end_matches(']');
    h == "localhost" || h.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback())
}

/// `host[:port]` of a URL, as allowlists name hosts.
fn authority(u: &reqwest::Url) -> String {
    match (u.host_str(), u.port()) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        (Some(h), None) => h.to_string(),
        _ => String::new(),
    }
}

impl Source {
    fn base(&self) -> String {
        format!("{}://{}", if loopback(&self.host) { "http" } else { "https" }, self.host)
    }

    fn allows(&self, u: &reqwest::Url, also: &[String]) -> bool {
        let a = authority(u);
        let ok_host = a == self.host || also.iter().any(|h| *h == a);
        let ok_scheme = u.scheme() == "https" || (u.scheme() == "http" && loopback(&a));
        ok_host && ok_scheme
    }
}

/// This node's platform as OCI names it.
fn platform() -> (&'static str, &'static str) {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        a => a,
    };
    ("linux", arch)
}

/// A credential: `user:password`, or a token.
enum Cred {
    Basic(Zeroizing<String>, Zeroizing<String>),
    Bearer(Zeroizing<String>),
}

impl Cred {
    fn parse(v: &str) -> Cred {
        match v.split_once(':') {
            Some((u, p)) => Cred::Basic(Zeroizing::new(u.into()), Zeroizing::new(p.into())),
            None => Cred::Bearer(Zeroizing::new(v.into())),
        }
    }
}

struct Client {
    http: reqwest::Client,
    src: Source,
    cred: Option<Cred>,
    /// The bearer token the registry's token service gave, once asked.
    token: Option<Zeroizing<String>>,
}

impl Client {
    fn new(src: Source, cred: Option<&str>) -> Result<Client> {
        let (allowed, src2) = ([src.blob_hosts.clone(), src.auth_hosts.clone()].concat(), src.clone());
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::custom(move |a| {
                if a.previous().len() >= 5 {
                    a.error("too many redirects")
                } else if src2.allows(a.url(), &allowed) {
                    a.follow()
                } else {
                    a.error(format!("a redirect to {}, which this registry isn't allowed", authority(a.url())))
                }
            }))
            .connect_timeout(std::time::Duration::from_secs(15))
            .user_agent(concat!("wicket/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Client { http, src, cred: cred.map(Cred::parse), token: None })
    }

    fn authorize(&self, r: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match (&self.token, &self.cred) {
            (Some(t), _) => r.bearer_auth(t.as_str()),
            (None, Some(Cred::Bearer(t))) => r.bearer_auth(t.as_str()),
            (None, Some(Cred::Basic(u, p))) => r.basic_auth(u.as_str(), Some(p.as_str())),
            (None, None) => r,
        }
    }

    /// GETs `path` under the registry, answering a token challenge once.
    async fn get(&mut self, path: &str, accept: &str) -> Result<reqwest::Response> {
        let url = format!("{}/v2/{}/{path}", self.src.base(), self.src.repository);
        for attempt in 0..2 {
            let r = self.authorize(self.http.get(&url).header(reqwest::header::ACCEPT, accept)).send().await.with_context(|| format!("GET {url}"))?;
            if r.status() == reqwest::StatusCode::UNAUTHORIZED && attempt == 0 {
                let challenge = r.headers().get(reqwest::header::WWW_AUTHENTICATE).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
                self.challenge(&challenge).await?;
                continue;
            }
            if !r.status().is_success() {
                bail!("GET {url}: {}", r.status());
            }
            return Ok(r);
        }
        bail!("GET {url}: refused after authenticating")
    }

    /// Answers a `WWW-Authenticate` challenge: a Bearer one from the token service (which must be
    /// the registry's own host or one of its `auth_hosts`), a Basic one with the credential.
    async fn challenge(&mut self, c: &str) -> Result<()> {
        let (scheme, params) = c.split_once(' ').unwrap_or((c, ""));
        if scheme.eq_ignore_ascii_case("basic") {
            if !matches!(self.cred, Some(Cred::Basic(..))) {
                bail!("the registry wants a user and password, and none is configured for it");
            }
            return Ok(());
        }
        if !scheme.eq_ignore_ascii_case("bearer") {
            bail!("the registry asks for {scheme:?} authentication");
        }
        let p = challenge_params(params);
        let realm = p.get("realm").context("a token challenge without a realm")?;
        let mut u = reqwest::Url::parse(realm).context("the token service's address")?;
        if !self.src.allows(&u, &self.src.auth_hosts) {
            bail!("the registry's token service is at {}, which isn't allowed for it (auth_hosts)", authority(&u));
        }
        {
            let mut q = u.query_pairs_mut();
            for k in ["service", "scope"] {
                if let Some(v) = p.get(k) {
                    q.append_pair(k, v);
                }
            }
        }
        let mut r = self.http.get(u.clone());
        r = match &self.cred {
            Some(Cred::Basic(user, pass)) => r.basic_auth(user.as_str(), Some(pass.as_str())),
            Some(Cred::Bearer(t)) => r.bearer_auth(t.as_str()),
            None => r,
        };
        let r = r.send().await.context("asking the registry's token service")?;
        if !r.status().is_success() {
            bail!("the registry's token service refused: {}", r.status());
        }
        #[derive(Deserialize)]
        struct T {
            token: Option<String>,
            access_token: Option<String>,
        }
        let t: T = r.json().await.context("the token service's answer")?;
        self.token = Some(Zeroizing::new(t.token.or(t.access_token).context("the token service gave no token")?));
        Ok(())
    }

    /// A small JSON document (manifest or index) by digest, checked against it.
    async fn manifest(&mut self, digest: &str) -> Result<Vec<u8>> {
        let accept = [crate::oci::INDEX_TYPES, crate::oci::MANIFEST_TYPES].concat().join(", ");
        let mut r = self.get(&format!("manifests/{digest}"), &accept).await?;
        let mut body = vec![];
        while let Some(c) = r.chunk().await? {
            body.extend_from_slice(&c);
            if body.len() as u64 > crate::oci::SMALL_MAX {
                bail!("manifest {digest} is too large");
            }
        }
        if format!("sha256:{}", hex::encode(Sha256::digest(&body))) != digest {
            bail!("the registry's manifest {digest} does not match its digest");
        }
        Ok(body)
    }

    /// Blob `digest` into `path`, hashed as it is written; it must be `size` bytes.
    async fn blob(&mut self, digest: &str, size: u64, path: &Path) -> Result<()> {
        let mut r = self.get(&format!("blobs/{digest}"), "*/*").await?;
        let part = path.with_extension("part");
        let mut f = tokio::fs::File::create(&part).await?;
        let mut h = Sha256::new();
        let mut n = 0u64;
        while let Some(c) = r.chunk().await.with_context(|| format!("fetching blob {digest}"))? {
            n += c.len() as u64;
            if n > size {
                bail!("blob {digest} is larger than its descriptor's {size} bytes");
            }
            h.update(&c);
            f.write_all(&c).await?;
        }
        f.flush().await?;
        if n != size || format!("sha256:{}", hex::encode(h.finalize())) != digest {
            let _ = tokio::fs::remove_file(&part).await;
            bail!("the registry's blob {digest} does not match its digest");
        }
        tokio::fs::rename(&part, path).await?;
        Ok(())
    }
}

/// `realm="…",service="…",scope="…"`.
fn challenge_params(s: &str) -> HashMap<String, String> {
    let mut m = HashMap::new();
    let mut rest = s.trim();
    while let Some((k, v)) = rest.split_once('=') {
        let k = k.trim().trim_start_matches(',').trim().to_ascii_lowercase();
        let v = v.trim_start();
        let (val, after) = match v.strip_prefix('"') {
            Some(q) => q.split_once('"').map_or((q, ""), |(a, b)| (a, b)),
            None => v.split_once(',').map_or((v, ""), |(a, b)| (a, b)),
        };
        m.insert(k, val.to_string());
        rest = after.trim_start_matches(',').trim();
    }
    m
}

/// Pulls image `pin` from `src` into `dir` (an empty directory), as a layout of that image alone,
/// named `name`. `cred` is the registry's credential, if it needs one. `max` caps the blobs' bytes.
pub async fn pull(src: &Source, pin: &str, name: Option<&str>, cred: Option<&str>, dir: &Path, max: u64) -> Result<crate::oci::Unpacked> {
    if crate::oci::hex_of(pin).is_none() {
        bail!("{pin:?} is not a sha256 digest");
    }
    let blobs = dir.join("blobs/sha256");
    tokio::fs::create_dir_all(&blobs).await?;
    let mut c = Client::new(src.clone(), cred)?;
    let mut have: HashMap<String, u64> = HashMap::new();
    let mut total = 0u64;
    let (os, arch) = platform();
    // Manifests to fetch, and whether each may be an index (only the pin's own children aren't).
    let mut todo = vec![(pin.to_string(), 0usize)];
    while let Some((d, depth)) = todo.pop() {
        if depth > 4 {
            bail!("the image's indexes nest too deep");
        }
        let body = c.manifest(&d).await?;
        tokio::fs::write(blobs.join(crate::oci::hex_of(&d).context("a digest")?), &body).await?;
        have.insert(d.clone(), body.len() as u64);
        let v: serde_json::Value = serde_json::from_slice(&body).with_context(|| format!("{d} is not an image index or manifest"))?;
        if let Some(ms) = v["manifests"].as_array() {
            let mine: Vec<&serde_json::Value> =
                ms.iter().filter(|m| m["platform"]["os"] == os && m["platform"]["architecture"] == arch).collect();
            let mine = if mine.is_empty() && ms.len() == 1 { ms.iter().collect() } else { mine };
            if mine.is_empty() {
                bail!("image {pin} has no manifest for {os}/{arch}");
            }
            for m in mine {
                todo.push((m["digest"].as_str().context("a descriptor without a digest")?.to_string(), depth + 1));
            }
        } else {
            let mut want = vec![&v["config"]];
            want.extend(v["layers"].as_array().context("a manifest without layers")?);
            for b in want {
                let bd = b["digest"].as_str().filter(|x| crate::oci::hex_of(x).is_some()).context("a descriptor without a sha256 digest")?;
                let size = b["size"].as_u64().context("a descriptor without a size")?;
                if have.contains_key(bd) {
                    continue;
                }
                total = total.saturating_add(size);
                if total > max {
                    bail!("image {pin} is larger than {max} bytes");
                }
                c.blob(bd, size, &blobs.join(crate::oci::hex_of(bd).expect("checked"))).await?;
                have.insert(bd.to_string(), size);
            }
        }
    }
    let (d, pin, name) = (dir.to_path_buf(), pin.to_string(), name.map(String::from));
    tokio::task::spawn_blocking(move || crate::oci::finish(&d, &have, &pin, name.as_deref())).await?
}

#[cfg(test)]
pub mod testkit {
    //! A registry for tests: serves an image's blobs by digest over HTTP on a loopback port, behind
    //! a token challenge if asked, and counts what it served.
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// This host's architecture, as OCI names it.
    pub const ARCH: &str = match std::env::consts::ARCH.as_bytes() {
        b"x86_64" => "amd64",
        b"aarch64" => "arm64",
        _ => std::env::consts::ARCH,
    };

    pub struct Fake {
        pub addr: std::net::SocketAddr,
        pub hits: Arc<Mutex<Vec<String>>>,
    }

    /// Serves `blobs` (digest to bytes) as `repo`'s manifests and blobs. With `login`
    /// (`user:password`), a token service at `/token` wants it and the registry wants its token.
    pub async fn serve(repo: &str, blobs: HashMap<String, Vec<u8>>, login: Option<&str>) -> Fake {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let hits = Arc::new(Mutex::new(vec![]));
        let (repo, blobs, h) = (repo.to_string(), Arc::new(blobs), hits.clone());
        use base64::Engine;
        let basic = login.map(|l| format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(l)));
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                let (repo, blobs, h, basic) = (repo.clone(), blobs.clone(), h.clone(), basic.clone());
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("").to_string();
                    let auth = req
                        .lines()
                        .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("authorization")).map(|(_, v)| v.trim().to_string()));
                    h.lock().unwrap().push(path.clone());
                    let (status, extra, body): (&str, String, Vec<u8>) = if path.starts_with("/token") {
                        match (&basic, &auth) {
                            (Some(b), Some(a)) if a == b => ("200 OK", String::new(), br#"{"token":"tok-1"}"#.to_vec()),
                            _ => ("401 Unauthorized", String::new(), vec![]),
                        }
                    } else if basic.is_some() && auth.as_deref() != Some("Bearer tok-1") {
                        let c = format!("WWW-Authenticate: Bearer realm=\"http://{addr}/token\",service=\"fake\",scope=\"repository:{repo}:pull\"\r\n");
                        ("401 Unauthorized", c, vec![])
                    } else {
                        let d = path
                            .strip_prefix(&format!("/v2/{repo}/manifests/"))
                            .or_else(|| path.strip_prefix(&format!("/v2/{repo}/blobs/")))
                            .unwrap_or("");
                        match blobs.get(d) {
                            Some(b) => ("200 OK", String::new(), b.clone()),
                            None => ("404 Not Found", String::new(), vec![]),
                        }
                    };
                    let head = format!("HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                    let _ = s.write_all(head.as_bytes()).await;
                    let _ = s.write_all(&body).await;
                });
            }
        });
        Fake { addr, hits }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::testkit::{image_with, sha};

    fn blobs_of(img: &crate::oci::testkit::Img) -> HashMap<String, Vec<u8>> {
        img.entries.iter().filter(|(p, _)| p.starts_with("blobs/sha256/")).map(|(p, b)| (format!("sha256:{}", &p[13..]), b.clone())).collect()
    }

    fn tmp() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-registry-test-{}-{}", std::process::id(), ulid::Ulid::new()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn challenges_parse() {
        let p = challenge_params(r#"realm="https://auth.example.com/token",service="registry.example.com",scope="repository:a/b:pull""#);
        assert_eq!(p["realm"], "https://auth.example.com/token");
        assert_eq!(p["scope"], "repository:a/b:pull");
        assert!(loopback("127.0.0.1:5000") && loopback("localhost") && loopback("[::1]:80") && !loopback("registry.example.com"));
    }

    #[tokio::test]
    async fn a_pull_by_digest_takes_this_platform_and_checks_every_blob() {
        let img = image_with(b"pulled layer");
        let fake = testkit::serve("team/agent", blobs_of(&img), Some("u:p")).await;
        let src = Source { host: fake.addr.to_string(), repository: "team/agent".into(), ..Default::default() };
        let d = tmp();
        let u = pull(&src, &img.index, Some("x/y@sha256:00"), Some("u:p"), &d, 1 << 30).await.unwrap();
        assert_eq!(u.manifests, 1);
        let hits = fake.hits.lock().unwrap().clone();
        assert!(hits.iter().any(|h| h.starts_with("/token")), "{hits:?}");
        assert!(!hits.iter().any(|h| h.ends_with(&sha(b"arm64")[7..])), "another platform's manifest isn't fetched: {hits:?}");
        std::fs::remove_dir_all(&d).unwrap();

        // Without the login, the token service refuses.
        let d = tmp();
        let e = pull(&src, &img.index, None, None, &d, 1 << 30).await.unwrap_err();
        assert!(format!("{e:#}").contains("token service refused"), "{e:#}");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[tokio::test]
    async fn a_tampered_blob_another_digest_or_another_host_is_refused() {
        let img = image_with(b"pulled layer");
        let mut blobs = blobs_of(&img);
        blobs.get_mut(&sha(b"pulled layer")).unwrap()[0] ^= 1;
        let fake = testkit::serve("team/agent", blobs, None).await;
        let src = Source { host: fake.addr.to_string(), repository: "team/agent".into(), ..Default::default() };
        let d = tmp();
        let e = pull(&src, &img.index, None, None, &d, 1 << 30).await.unwrap_err();
        assert!(format!("{e:#}").contains("does not match its digest"), "{e:#}");
        let e = pull(&src, &sha(b"not there"), None, None, &d, 1 << 30).await.unwrap_err();
        assert!(format!("{e:#}").contains("404"), "{e:#}");
        std::fs::remove_dir_all(&d).unwrap();
        // A token service elsewhere than the registry and its auth_hosts is never asked.
        let img2 = image_with(b"x");
        let fake2 = testkit::serve("team/agent", blobs_of(&img2), Some("u:p")).await;
        let src = Source { host: format!("localhost:{}", fake2.addr.port()), repository: "team/agent".into(), ..Default::default() };
        let d = tmp();
        let e = pull(&src, &img2.index, None, Some("u:p"), &d, 1 << 30).await.unwrap_err();
        assert!(format!("{e:#}").contains("isn't allowed for it"), "{e:#}");
        assert!(!fake2.hits.lock().unwrap().iter().any(|h| h.starts_with("/token")));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
