//! Control-plane state off the host (#154): where the installation keeps what it can't lose with
//! its control host. `<data dir>/state-store.yaml`:
//!
//! ```yaml
//! s3:                                   # an S3-compatible store
//!   endpoint: https://s3.eu-west-2.amazonaws.com
//!   bucket: example-wicket
//!   prefix: prod/                       # optional
//!   region: eu-west-2
//!   path_style: true                    # default
//!   access_key_id: AKIA…
//!   secret: s3-wicket                   # vault secret: the secret access key, bound to the endpoint
//! bundles: s3                           # hibernated agents' bundles: s3 or local (default local)
//! ledger:                               # stream the ledger to the store (Litestream)
//!   sync_interval: 1s
//!   retention: 72h
//!   litestream: { binary: /usr/local/bin/litestream }   # or { image: litestream/litestream@sha256:… }
//! ```
//!
//! Audit segments go to the store through an audit sink of type `store` (`audit-sinks.yaml`).

use crate::data_dir;
use crate::s3::{Creds, S3Config, S3Store};
use anyhow::{bail, Context, Result};
use std::path::PathBuf;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Where {
    #[default]
    Local,
    S3,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateStore {
    #[serde(default)]
    pub s3: Option<S3Config>,
    #[serde(default)]
    pub bundles: Where,
    #[serde(default)]
    pub ledger: Option<LedgerStream>,
}

/// The ledger streamed to the store, with point-in-time restore.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerStream {
    /// How often the WAL is shipped: the most a lost control host loses.
    #[serde(default = "default_sync")]
    pub sync_interval: String,
    /// How far back a point-in-time restore can go.
    #[serde(default = "default_retention")]
    pub retention: String,
    pub litestream: Litestream,
}

fn default_sync() -> String {
    "1s".into()
}
fn default_retention() -> String {
    "72h".into()
}

/// How Litestream runs: a binary on this host, or its image (run with host networking, the data
/// directory mounted at the same path, as this user).
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Litestream {
    #[serde(default)]
    pub binary: Option<String>,
    #[serde(default)]
    pub image: Option<String>,
}

pub fn path() -> PathBuf {
    data_dir().join("state-store.yaml")
}

impl StateStore {
    pub fn parse(text: &str) -> Result<StateStore> {
        let s: StateStore = serde_yaml::from_str(text)?;
        s.check()?;
        Ok(s)
    }

    pub fn check(&self) -> Result<()> {
        if let Some(c) = &self.s3 {
            c.check()?;
        }
        if self.s3.is_none() && (self.bundles == Where::S3 || self.ledger.is_some()) {
            bail!("bundles: s3 and ledger: need an s3: store");
        }
        if let Some(l) = &self.ledger {
            humantime::parse_duration(&l.sync_interval).context("ledger.sync_interval")?;
            humantime::parse_duration(&l.retention).context("ledger.retention")?;
            if l.litestream.binary.is_some() == l.litestream.image.is_some() {
                bail!("ledger.litestream: one of binary or image");
            }
        }
        Ok(())
    }

    /// The installation's, if it has a `state-store.yaml`.
    pub fn load() -> Result<Option<StateStore>> {
        let p = path();
        match std::fs::read_to_string(&p) {
            Ok(t) => Ok(Some(StateStore::parse(&t).with_context(|| format!("{}", p.display()))?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("{}", p.display())),
        }
    }

    pub fn s3(&self) -> Result<&S3Config> {
        self.s3.as_ref().context("state-store.yaml has no s3: store")
    }

    /// The S3 store's credentials: the secret from the vault, if it may go to the endpoint's host.
    pub fn creds(&self) -> Result<Creds> {
        let c = self.s3()?;
        let v = wicket_proxy::vault::Vault::new(wicket_proxy::vault::Vault::default_dir());
        let secret = v.get_for(&c.secret, &c.host()?).with_context(|| format!("the store's secret {:?}", c.secret))?;
        Ok(Creds { access_key_id: c.access_key_id.clone(), secret_access_key: secret.trim().to_string() })
    }

    pub fn open_s3(&self) -> Result<S3Store> {
        S3Store::new(self.s3()?.clone(), self.creds()?, data_dir().join("objects-scratch"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_state_store_is_checked() {
        let ok = "s3: { endpoint: 'https://s3.example.com', bucket: b-1, access_key_id: k, secret: s3 }\nbundles: s3\nledger: { litestream: { image: 'litestream/litestream:0.5.18' } }\n";
        let s = StateStore::parse(ok).unwrap();
        assert!(s.s3.as_ref().unwrap().path_style && s.ledger.as_ref().unwrap().sync_interval == "1s");
        assert!(StateStore::parse("bundles: s3\n").is_err());
        assert!(StateStore::parse(&ok.replace("image:", "nope:")).is_err());
        assert!(StateStore::parse(&ok.replace("b-1", "B_1")).is_err());
        assert!(StateStore::parse(&ok.replace("{ image: 'litestream/litestream:0.5.18' }", "{}")).is_err());
        assert!(StateStore::parse(&ok.replace("https://s3.example.com", "ftp://x")).is_err());
    }
}
