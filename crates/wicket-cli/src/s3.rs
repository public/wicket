//! An S3-compatible object store (#154): agent bundles and audit segments off the control host.
//!
//! A small client of its own: AWS Signature Version 4 over reqwest, for the four calls
//! [`ObjectStore`] needs (put-if-absent, get, delete, list by prefix). Path-style or virtual-host
//! addressing; `If-None-Match: *` for put-if-absent where the store supports it (S3, R2, GCS and
//! versitygw do), or a HEAD first where it doesn't (`conditional_put: false`: not atomic, which is
//! fine for wicket's keys, which are content hashes or name a sequence number and generation).
//!
//! [`ObjectStore`] is synchronous: each call runs on a small runtime of its own and the caller
//! waits, so it works from a thread inside or outside tokio. Objects are spooled through a scratch
//! file, so neither direction holds an object in memory.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, Write};
use std::path::PathBuf;
use std::sync::OnceLock;
use wicket_store::objects::{valid_key, ObjectStore};

/// Where an S3-compatible store is and how to reach it (`state-store.yaml`, `s3:`).
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct S3Config {
    /// `https://s3.eu-west-2.amazonaws.com`, `https://<account>.r2.cloudflarestorage.com`, …
    pub endpoint: String,
    pub bucket: String,
    /// Prepended to every key (`wicket/prod/`, say); empty for none.
    #[serde(default)]
    pub prefix: String,
    #[serde(default = "default_region")]
    pub region: String,
    /// `https://endpoint/bucket/key` (most S3-compatible stores) instead of `https://bucket.endpoint/key`.
    #[serde(default = "yes")]
    pub path_style: bool,
    pub access_key_id: String,
    /// The vault secret holding the secret access key (bound to the endpoint's host).
    pub secret: String,
    /// Put-if-absent with `If-None-Match: *` (default), or a HEAD then a PUT.
    #[serde(default = "yes")]
    pub conditional_put: bool,
}

fn default_region() -> String {
    "us-east-1".into()
}
fn yes() -> bool {
    true
}

impl S3Config {
    pub fn host(&self) -> Result<String> {
        let u = url::Url::parse(&self.endpoint).with_context(|| format!("endpoint {}", self.endpoint))?;
        if !matches!(u.scheme(), "https" | "http") {
            bail!("endpoint {}: not http(s)", self.endpoint);
        }
        Ok(u.host_str().context("endpoint has no host")?.to_string())
    }

    pub fn check(&self) -> Result<()> {
        self.host()?;
        let ok = |s: &str| {
            !s.is_empty() && s.len() <= 63 && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.')
        };
        if !ok(&self.bucket) {
            bail!("bucket {:?}: lowercase letters, digits, '-' and '.'", self.bucket);
        }
        if !self.prefix.is_empty() && !(self.prefix.ends_with('/') && valid_key(self.prefix.trim_end_matches('/'))) {
            bail!("prefix {:?}: object-key segments, ending in '/'", self.prefix);
        }
        Ok(())
    }
}

/// The credentials a request is signed with.
#[derive(Clone)]
pub struct Creds {
    pub access_key_id: String,
    pub secret_access_key: String,
}

pub struct S3Store {
    cfg: S3Config,
    creds: Creds,
    scratch: PathBuf,
    client: reqwest::Client,
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("wicket-s3")
            .enable_all()
            .build()
            .expect("the S3 client's runtime")
    })
}

/// Runs `f` on the client's runtime and waits for it, from any thread.
fn block<T: Send + 'static>(f: impl std::future::Future<Output = T> + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    runtime().spawn(async move {
        let _ = tx.send(f.await);
    });
    rx.recv().expect("the S3 client's runtime")
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

impl S3Store {
    pub fn new(cfg: S3Config, creds: Creds, scratch: PathBuf) -> Result<S3Store> {
        cfg.check()?;
        let client = reqwest::Client::builder().timeout(std::time::Duration::from_secs(600)).build()?;
        Ok(S3Store { cfg, creds, scratch, client })
    }

    /// The URL and the canonical path of `key` (or of the bucket, for an empty key).
    fn url(&self, key: &str) -> Result<(url::Url, String, String)> {
        let base = url::Url::parse(&self.cfg.endpoint)?;
        let host = base.host_str().context("endpoint host")?.to_string();
        let full = format!("{}{key}", if key.is_empty() { "" } else { &self.cfg.prefix });
        let (host, path) = match self.cfg.path_style {
            true => (host, format!("/{}/{}", self.cfg.bucket, full)),
            false => (format!("{}.{host}", self.cfg.bucket), format!("/{full}")),
        };
        let host_port = match base.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.clone(),
        };
        let path = if key.is_empty() && self.cfg.path_style { format!("/{}", self.cfg.bucket) } else { path };
        let canon = uri_encode(&path, false);
        let u = url::Url::parse(&format!("{}://{host_port}{canon}", base.scheme()))?;
        Ok((u, host_port, canon))
    }

    /// A signed request. `query` is unencoded; `payload` the body's SHA-256 (hex).
    fn request(&self, method: reqwest::Method, key: &str, query: &[(&str, &str)], payload: &str) -> Result<reqwest::RequestBuilder> {
        let (mut u, host, path) = self.url(key)?;
        let now = time::OffsetDateTime::now_utc();
        let amz = now.format(&time::macros::format_description!("[year][month][day]T[hour][minute][second]Z"))?;
        let mut q: Vec<(String, String)> = query.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        q.sort();
        let canon_q = q.iter().map(|(k, v)| format!("{}={}", uri_encode(k, true), uri_encode(v, true))).collect::<Vec<_>>().join("&");
        if !canon_q.is_empty() {
            u.set_query(Some(&canon_q));
        }
        let headers = [("host", host.as_str()), ("x-amz-content-sha256", payload), ("x-amz-date", amz.as_str())];
        let auth = authorization(&self.creds, &self.cfg.region, method.as_str(), &path, &canon_q, &headers, payload, &amz);
        Ok(self.client.request(method, u).header("x-amz-content-sha256", payload).header("x-amz-date", amz).header("authorization", auth))
    }

    fn scratch_file(&self) -> io::Result<std::fs::File> {
        std::fs::create_dir_all(&self.scratch)?;
        let p = self.scratch.join(format!(".s3-{}-{}", std::process::id(), ulid::Ulid::new()));
        let f = std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&p)?;
        let _ = std::fs::remove_file(&p);
        Ok(f)
    }

    fn exists(&self, key: &str) -> io::Result<bool> {
        let req = self.request(reqwest::Method::HEAD, key, &[], EMPTY_SHA256).map_err(io_err)?;
        let status = block(async move { req.send().await.map(|r| r.status()) }).map_err(io_err)?;
        match status.as_u16() {
            200 => Ok(true),
            404 => Ok(false),
            s => Err(io_err(format!("HEAD {key}: HTTP {s}"))),
        }
    }

    /// Writes `key` whatever is there (small objects only: the ledger's lineage list).
    pub fn put_overwrite(&self, key: &str, body: Vec<u8>) -> Result<()> {
        if !valid_key(key) {
            bail!("bad object key {key:?}");
        }
        let sha = hex::encode(Sha256::digest(&body));
        let req = self.request(reqwest::Method::PUT, key, &[], &sha)?.header("content-length", body.len()).body(body);
        let key2 = key.to_string();
        block(async move {
            let r = req.send().await?;
            match r.status().as_u16() {
                200 | 201 | 204 => Ok(()),
                s => bail!("PUT {key2}: HTTP {s}"),
            }
        })
    }

    /// Checks the store can be reached and written: puts, reads back and deletes a probe object.
    pub fn probe(&self) -> Result<()> {
        let key = format!("probe/{}", ulid::Ulid::new().to_string().to_lowercase());
        self.put_if_absent(&key, &mut &b"wicket"[..])?;
        let mut back = String::new();
        self.get(&key)?.context("the probe object isn't there after writing it")?.read_to_string(&mut back)?;
        self.delete(&key)?;
        if back != "wicket" {
            bail!("the probe object read back differently");
        }
        Ok(())
    }
}

const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

impl ObjectStore for S3Store {
    fn put_if_absent(&self, key: &str, data: &mut dyn Read) -> io::Result<bool> {
        if !valid_key(key) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("bad object key {key:?}")));
        }
        if !self.cfg.conditional_put && self.exists(key)? {
            return Ok(false);
        }
        // Spooled, for its length and hash (the signature covers the body).
        let mut f = self.scratch_file()?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        let mut len = 0u64;
        loop {
            let k = data.read(&mut buf)?;
            if k == 0 {
                break;
            }
            h.update(&buf[..k]);
            f.write_all(&buf[..k])?;
            len += k as u64;
        }
        f.flush()?;
        f.rewind()?;
        let sha = hex::encode(h.finalize());
        let mut req = self.request(reqwest::Method::PUT, key, &[], &sha).map_err(io_err)?.header("content-length", len);
        if self.cfg.conditional_put {
            req = req.header("if-none-match", "*");
        }
        // A 409 (ConditionalRequestConflict) is a concurrent conditional write still in progress:
        // tried again, a moment later, from the spooled copy.
        let key2 = key.to_string();
        for attempt in 0..4 {
            let body = reqwest::Body::from(tokio::fs::File::from_std(f.try_clone()?));
            let req = req.try_clone().ok_or_else(|| io_err("PUT can't be retried"))?;
            let key3 = key2.clone();
            let got = block(async move {
                let r = req.body(body).send().await.map_err(io_err)?;
                match r.status().as_u16() {
                    200 | 201 | 204 => Ok(Some(true)),
                    // Someone (an earlier attempt) wrote it first.
                    412 => Ok(Some(false)),
                    409 => Ok(None),
                    s => Err(io_err(format!("PUT {key3}: HTTP {s}: {}", wicket_agent::clip(&r.text().await.unwrap_or_default(), 300)))),
                }
            })?;
            if let Some(done) = got {
                return Ok(done);
            }
            std::thread::sleep(std::time::Duration::from_millis(200 << attempt));
            f.rewind()?;
        }
        Err(io_err(format!("PUT {key2}: a conflicting write kept it busy (HTTP 409)")))
    }

    fn get(&self, key: &str) -> io::Result<Option<Box<dyn Read + Send>>> {
        if !valid_key(key) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("bad object key {key:?}")));
        }
        let req = self.request(reqwest::Method::GET, key, &[], EMPTY_SHA256).map_err(io_err)?;
        let f = self.scratch_file()?;
        let mut out = f.try_clone()?;
        let key2 = key.to_string();
        let found = block(async move {
            use futures_util::StreamExt;
            let r = req.send().await.map_err(io_err)?;
            match r.status().as_u16() {
                200 => {}
                404 => return Ok(false),
                s => return Err(io_err(format!("GET {key2}: HTTP {s}"))),
            }
            let mut s = r.bytes_stream();
            while let Some(c) = s.next().await {
                out.write_all(&c.map_err(io_err)?)?;
            }
            out.flush()?;
            Ok::<_, io::Error>(true)
        })?;
        if !found {
            return Ok(None);
        }
        let mut f = f;
        f.rewind()?;
        Ok(Some(Box::new(io::BufReader::new(f))))
    }

    fn delete(&self, key: &str) -> io::Result<()> {
        let req = self.request(reqwest::Method::DELETE, key, &[], EMPTY_SHA256).map_err(io_err)?;
        let key2 = key.to_string();
        block(async move {
            let r = req.send().await.map_err(io_err)?;
            match r.status().as_u16() {
                200 | 204 | 404 => Ok(()),
                s => Err(io_err(format!("DELETE {key2}: HTTP {s}"))),
            }
        })
    }

    fn list_prefix(&self, prefix: &str) -> io::Result<Vec<String>> {
        let full = format!("{}{prefix}", self.cfg.prefix);
        let mut keys = vec![];
        let mut token: Option<String> = None;
        loop {
            let mut q = vec![("list-type", "2"), ("prefix", full.as_str())];
            if let Some(t) = &token {
                q.push(("continuation-token", t.as_str()));
            }
            let req = self.request(reqwest::Method::GET, "", &q, EMPTY_SHA256).map_err(io_err)?;
            let body = block(async move {
                let r = req.send().await.map_err(io_err)?;
                let s = r.status().as_u16();
                let t = r.text().await.map_err(io_err)?;
                if s != 200 {
                    return Err(io_err(format!("LIST: HTTP {s}: {}", wicket_agent::clip(&t, 300))));
                }
                Ok(t)
            })?;
            for k in xml_values(&body, "Key") {
                if let Some(k) = k.strip_prefix(&self.cfg.prefix) {
                    keys.push(k.to_string());
                }
            }
            token = match xml_values(&body, "IsTruncated").first().map(|s| s.as_str()) {
                Some("true") => xml_values(&body, "NextContinuationToken").into_iter().next(),
                _ => None,
            };
            if token.is_none() {
                break;
            }
        }
        keys.sort();
        Ok(keys)
    }
}

/// Every `<tag>…</tag>` value in a (flat enough) S3 XML answer, unescaped.
fn xml_values(xml: &str, tag: &str) -> Vec<String> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut out = vec![];
    let mut rest = xml;
    while let Some(a) = rest.find(&open) {
        let after = &rest[a + open.len()..];
        let Some(b) = after.find(&close) else { break };
        out.push(after[..b].replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'").replace("&amp;", "&"));
        rest = &after[b + close.len()..];
    }
    out
}

/// SigV4's URI encoding: everything but unreserved characters (and `/`, in a path).
fn uri_encode(s: &str, slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            b'/' if !slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// The `Authorization` header of a SigV4 request: `headers` are lowercase names with their values,
/// all of them signed; `path` and `query` already canonical.
#[allow(clippy::too_many_arguments)]
fn authorization(
    c: &Creds,
    region: &str,
    method: &str,
    path: &str,
    query: &str,
    headers: &[(&str, &str)],
    payload: &str,
    amz: &str,
) -> String {
    let mut hs: Vec<(&str, &str)> = headers.to_vec();
    hs.sort();
    let canon_h: String = hs.iter().map(|(k, v)| format!("{k}:{}\n", v.trim())).collect();
    let signed = hs.iter().map(|(k, _)| *k).collect::<Vec<_>>().join(";");
    let creq = format!("{method}\n{path}\n{query}\n{canon_h}\n{signed}\n{payload}");
    let date = &amz[..8];
    let scope = format!("{date}/{region}/s3/aws4_request");
    let sts = format!("AWS4-HMAC-SHA256\n{amz}\n{scope}\n{}", hex::encode(Sha256::digest(creq.as_bytes())));
    let k = hmac(format!("AWS4{}", c.secret_access_key).as_bytes(), date.as_bytes());
    let k = hmac(&k, region.as_bytes());
    let k = hmac(&k, b"s3");
    let k = hmac(&k, b"aws4_request");
    let sig = hex::encode(hmac(&k, sts.as_bytes()));
    format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={sig}", c.access_key_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AWS's own worked example (S3 API reference, "Signature Calculations for the Authorization
    /// Header", GET Object): the published signature for the published example credentials.
    #[test]
    fn sigv4_matches_the_published_example() {
        let c = Creds {
            access_key_id: ["AKIAIOSFODNN7", "EXAMPLE"].concat(),
            secret_access_key: ["wJalrXUtnFEMI/K7MDENG/bPxRfiCY", "EXAMPLEKEY"].concat(),
        };
        let a = authorization(
            &c,
            "us-east-1",
            "GET",
            "/test.txt",
            "",
            &[
                ("host", "examplebucket.s3.amazonaws.com"),
                ("range", "bytes=0-9"),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", "20130524T000000Z"),
            ],
            EMPTY_SHA256,
            "20130524T000000Z",
        );
        assert!(a.ends_with("Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"), "{a}");
        assert!(a.contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date"));
    }

    #[test]
    fn hmac_matches_rfc_4231() {
        // RFC 4231 test case 2.
        assert_eq!(
            hex::encode(hmac(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn list_answers_are_read() {
        let x = "<ListBucketResult><IsTruncated>true</IsTruncated><Contents><Key>p/a&amp;b</Key></Contents><Contents><Key>p/c</Key></Contents><NextContinuationToken>t1</NextContinuationToken></ListBucketResult>";
        assert_eq!(xml_values(x, "Key"), ["p/a&b", "p/c"]);
        assert_eq!(xml_values(x, "NextContinuationToken"), ["t1"]);
        assert_eq!(uri_encode("a b/c+d", false), "a%20b/c%2Bd");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
    }
}
