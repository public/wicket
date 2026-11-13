//! Where bundles go: wicket's own object stores (its `DirStore`, and its S3 client, included from
//! `crates/wicket-cli/src/s3.rs` unchanged), and an `age` sealing layer that stands in for
//! `SealedStore` (option 3: the minimal change).

use anyhow::{bail, Context, Result};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use wicket_store::objects::{DirStore, ObjectStore};

#[path = "../../../crates/wicket-cli/src/s3.rs"]
#[allow(dead_code, clippy::all)]
mod s3;

/// `fs:<dir>` or `s3:<endpoint>|<bucket>|<prefix>` (credentials from `E5_S3_KEY`/`E5_S3_SECRET`).
#[derive(Clone, Debug)]
pub enum Spec {
    Fs(PathBuf),
    S3 { endpoint: String, bucket: String, prefix: String },
}

impl Spec {
    pub fn parse(s: &str) -> Result<Spec> {
        if let Some(d) = s.strip_prefix("fs:") {
            return Ok(Spec::Fs(PathBuf::from(d)));
        }
        if let Some(r) = s.strip_prefix("s3:") {
            let p: Vec<&str> = r.split('|').collect();
            if p.len() != 3 {
                bail!("s3:<endpoint>|<bucket>|<prefix>");
            }
            return Ok(Spec::S3 { endpoint: p[0].into(), bucket: p[1].into(), prefix: p[2].into() });
        }
        bail!("store: fs:<dir> or s3:<endpoint>|<bucket>|<prefix>")
    }

}

pub fn creds() -> (String, String) {
    (std::env::var("E5_S3_KEY").unwrap_or_else(|_| "e5key".into()), std::env::var("E5_S3_SECRET").unwrap_or_else(|_| "e5secret-e5secret".into()))
}

pub fn open(spec: &Spec, scratch: &Path) -> Result<Box<dyn ObjectStore>> {
    Ok(match spec {
        Spec::Fs(d) => {
            std::fs::create_dir_all(d)?;
            Box::new(DirStore::new(d.clone()))
        }
        Spec::S3 { endpoint, bucket, prefix } => {
            let (k, s) = creds();
            let cfg: s3::S3Config = serde_json::from_value(serde_json::json!({
                "endpoint": endpoint, "bucket": bucket, "prefix": prefix, "region": "us-east-1", "path_style": true,
                "access_key_id": k, "secret": "unused", "conditional_put": true
            }))
            .context("s3 config")?;
            let creds = s3::Creds { access_key_id: k, secret_access_key: s };
            std::fs::create_dir_all(scratch)?;
            Box::new(s3::S3Store::new(cfg, creds, scratch.to_path_buf())?)
        }
    })
}

/// An object store whose objects are sealed with `age` (X25519 recipient, the format's own
/// streaming STREAM construction with 64 KiB chunks), under `age/<key>`. The binding of an object to
/// its key, which `SealedStore` puts in each chunk's associated data, has no slot in age: here the
/// key is written as the first line of the plaintext and checked on read.
pub struct AgeStore<S> {
    inner: S,
    identity: age::x25519::Identity,
    scratch: PathBuf,
}

impl<S: ObjectStore> AgeStore<S> {
    pub fn new(inner: S, identity: age::x25519::Identity, scratch: PathBuf) -> AgeStore<S> {
        AgeStore { inner, identity, scratch }
    }
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

impl<S: ObjectStore> ObjectStore for AgeStore<S> {
    fn put_if_absent(&self, key: &str, data: &mut dyn Read) -> io::Result<bool> {
        let tmp = self.scratch.join(format!("age-{}-{}", std::process::id(), key.replace('/', "_")));
        {
            let f = std::fs::File::create(&tmp)?;
            let recipient = self.identity.to_public();
            let enc = age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient)).map_err(io_err)?;
            let mut w = enc.wrap_output(io::BufWriter::new(f)).map_err(io_err)?;
            w.write_all(key.as_bytes())?;
            w.write_all(b"\n")?;
            io::copy(data, &mut w)?;
            w.finish()?.flush()?;
        }
        let r = self.inner.put_if_absent(&format!("age/{key}"), &mut io::BufReader::new(std::fs::File::open(&tmp)?));
        let _ = std::fs::remove_file(&tmp);
        r
    }

    fn get(&self, key: &str) -> io::Result<Option<Box<dyn Read + Send>>> {
        let Some(r) = self.inner.get(&format!("age/{key}"))? else { return Ok(None) };
        let dec = age::Decryptor::new_buffered(io::BufReader::new(r)).map_err(io_err)?;
        let mut rd = io::BufReader::new(dec.decrypt(std::iter::once(&self.identity as &dyn age::Identity)).map_err(io_err)?);
        let mut first = String::new();
        io::BufRead::read_line(&mut rd, &mut first)?;
        if first.trim_end_matches('\n') != key {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("age object is for {first:?}, not {key}")));
        }
        Ok(Some(Box::new(rd)))
    }

    fn delete(&self, key: &str) -> io::Result<()> {
        self.inner.delete(&format!("age/{key}"))
    }

    fn list_prefix(&self, prefix: &str) -> io::Result<Vec<String>> {
        Ok(self.inner.list_prefix(&format!("age/{prefix}"))?.into_iter().filter_map(|k| k.strip_prefix("age/").map(String::from)).collect())
    }
}
