//! Certificates from an ACME CA (Let's Encrypt by default) for the console's own HTTPS.
//!
//! Validation is TLS-ALPN-01 (RFC 8737): the CA connects to the console's listener on :443 with ALPN
//! `acme-tls/1`, and the console's certificate resolver ([`super::tls::CertResolver`]) answers with a
//! challenge certificate. So the console needs only :443 reachable: no :80 listener, no DNS API
//! credentials on the box.
//!
//! Client: `instant-acme` (maintained by a rustls maintainer, async, ring-backed). The
//! alternative, `rustls-acme`, drives the whole loop itself but brings a second HTTP/TLS stack
//! (futures-rustls, async-web-client); with instant-acme wicket keeps its own listener and resolver,
//! and supplies the HTTP client (reqwest, already a dependency), which is also where the tests
//! plug in a mock CA.
//!
//! State lives in the cache directory (default `$WICKET_HOME/acme`, mode 0700): the ACME account
//! (`account-<directory hash>.json`) and the certificate and key (`<domain>.crt.pem`,
//! `<domain>.key.pem`), files mode 0600. A cached certificate is reused at start-up until it is
//! within [`RENEW_BEFORE`] of expiry; a renewal task checks twice a day.

use super::tls::{self, CertResolver};
use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, BodyWrapper, BytesResponse, ChallengeType, HttpClient, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use sha2::Digest;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
/// Renew when the certificate has less than this left (Let's Encrypt certificates last 90 days or less).
pub const RENEW_BEFORE: i64 = 30 * 86400;

/// Makes the HTTP client the ACME account talks through.
pub type HttpFactory = Arc<dyn Fn() -> Box<dyn HttpClient> + Send + Sync>;

#[derive(Clone, Debug)]
pub struct AcmeConfig {
    pub domain: String,
    /// Contact URIs for the account (`mailto:ops@example.com`); may be empty.
    pub contact: Vec<String>,
    pub directory: String,
    pub cache: PathBuf,
}

/// Whether `s` is a DNS name an ACME CA can validate (and safe as a file name).
pub fn valid_domain(s: &str) -> bool {
    s.len() <= 253
        && s.contains('.')
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        && !s.chars().all(|c| c.is_ascii_digit() || c == '.')
}

impl AcmeConfig {
    fn account_path(&self) -> PathBuf {
        let h = hex::encode(sha2::Sha256::digest(self.directory.as_bytes()));
        self.cache.join(format!("account-{}.json", &h[..12]))
    }

    pub fn cert_path(&self) -> PathBuf {
        self.cache.join(format!("{}.crt.pem", self.domain))
    }

    pub fn key_path(&self) -> PathBuf {
        self.cache.join(format!("{}.key.pem", self.domain))
    }

    /// The cached certificate, if there is one that loads.
    pub fn cached(&self) -> Option<rustls::sign::CertifiedKey> {
        let chain = std::fs::read(self.cert_path()).ok()?;
        let key = std::fs::read(self.key_path()).ok()?;
        tls::certified_key_from_pem(&chain, &key).ok()
    }
}

/// Writes a secret file atomically: 0600, in a 0700 directory.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let dir = path.parent().ok_or_else(|| anyhow!("{} has no directory", path.display()))?;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

async fn account(cfg: &AcmeConfig, http: &HttpFactory) -> Result<Account> {
    let path = cfg.account_path();
    if let Ok(bytes) = std::fs::read(&path) {
        let creds: AccountCredentials = serde_json::from_slice(&bytes).with_context(|| format!("{}", path.display()))?;
        return Ok(Account::builder_with_http(http()).from_credentials(creds).await?);
    }
    let contact: Vec<&str> = cfg.contact.iter().map(String::as_str).collect();
    let (account, creds) = Account::builder_with_http(http())
        .create(&NewAccount { contact: &contact, terms_of_service_agreed: true, only_return_existing: false }, cfg.directory.clone(), None)
        .await
        .context("creating the ACME account")?;
    write_private(&path, &serde_json::to_vec(&creds)?)?;
    Ok(account)
}

/// Orders a certificate for the domain, answering the TLS-ALPN-01 challenge through `resolver`
/// (so the console's listener must already be serving), stores it and puts it in service.
pub async fn order(cfg: &AcmeConfig, resolver: &CertResolver, http: &HttpFactory, poll: RetryPolicy) -> Result<()> {
    let account = account(cfg, http).await?;
    let ids = [Identifier::Dns(cfg.domain.clone())];
    let mut order = account.new_order(&NewOrder::new(&ids)).await.context("new ACME order")?;
    let mut authzs = order.authorizations();
    while let Some(a) = authzs.next().await {
        let mut a = a?;
        match a.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            s => bail!("the ACME authorization for {} is {s:?}", cfg.domain),
        }
        let mut ch = a.challenge(ChallengeType::TlsAlpn01).ok_or_else(|| anyhow!("the ACME server offers no tls-alpn-01 challenge"))?;
        let cert = tls::challenge_cert(&cfg.domain, ch.key_authorization().digest().as_ref())?;
        resolver.set_challenge(&cfg.domain, Arc::new(cert));
        ch.set_ready().await?;
    }
    let status = order.poll_ready(&poll).await;
    resolver.clear_challenge(&cfg.domain);
    match status.context("waiting for the ACME validation")? {
        OrderStatus::Ready => {}
        s => bail!("the ACME order for {} is {s:?} (is :443 reachable at that name?)", cfg.domain),
    }
    let key_pem = order.finalize().await.context("finalizing the ACME order")?;
    let chain_pem = order.poll_certificate(&poll).await.context("fetching the certificate")?;
    let ck = tls::certified_key_from_pem(chain_pem.as_bytes(), key_pem.as_bytes())?;
    write_private(&cfg.key_path(), key_pem.as_bytes())?;
    write_private(&cfg.cert_path(), chain_pem.as_bytes())?;
    resolver.set(Arc::new(ck));
    tracing::info!("ACME certificate for {} in service", cfg.domain);
    Ok(())
}

/// Whether it is time to order: no certificate, or less than [`RENEW_BEFORE`] left.
pub(crate) fn due(resolver: &CertResolver, now: i64) -> bool {
    resolver.current().and_then(|ck| tls::not_after(&ck).ok()).is_none_or(|t| t - now < RENEW_BEFORE)
}

/// Puts the cached certificate in service if it is not due for renewal; otherwise orders one. Then
/// keeps it renewed: checks every `every`, retrying a failed order at the next check.
pub fn run(cfg: AcmeConfig, resolver: Arc<CertResolver>, http: HttpFactory, every: Duration) {
    if let Some(ck) = cfg.cached() {
        resolver.set(Arc::new(ck));
    }
    tokio::spawn(async move {
        loop {
            if due(&resolver, wicket_store::now()) {
                let poll = RetryPolicy::new().initial_delay(Duration::from_secs(1)).backoff(1.5).timeout(Duration::from_secs(180));
                if let Err(e) = order(&cfg, &resolver, &http, poll).await {
                    tracing::warn!("ACME: {e:#}");
                    eprintln!(
                        "wicket serve: ACME certificate for {} failed: {e:#} (retrying in {})",
                        cfg.domain,
                        humantime::format_duration(every)
                    );
                }
            }
            tokio::time::sleep(every).await;
        }
    });
}

/// The ACME HTTP client: reqwest (rustls, the webpki roots), HTTPS only.
pub fn reqwest_http() -> HttpFactory {
    Arc::new(|| {
        let client = reqwest::Client::builder().https_only(true).timeout(Duration::from_secs(30)).build().expect("reqwest client");
        Box::new(ReqwestHttp(client)) as Box<dyn HttpClient>
    })
}

struct ReqwestHttp(reqwest::Client);

fn other(e: impl std::error::Error + Send + Sync + 'static) -> instant_acme::Error {
    instant_acme::Error::Other(Box::new(e))
}

impl HttpClient for ReqwestHttp {
    fn request(
        &self,
        req: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let client = self.0.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let body = body.collect().await.map_err(other)?.to_bytes();
            let rsp = client.request(parts.method, parts.uri.to_string()).headers(parts.headers).body(body).send().await.map_err(other)?;
            let mut out = http::Response::builder().status(rsp.status());
            for (k, v) in rsp.headers() {
                out = out.header(k, v);
            }
            let bytes = rsp.bytes().await.map_err(other)?;
            Ok(BytesResponse::from(out.body(Full::new(bytes))?))
        })
    }
}
