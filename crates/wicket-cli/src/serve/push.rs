//! Web Push notifications for the console: a push to each subscribed device when a new request is
//! waiting (RFC 8030 delivery, RFC 8291 message encryption, RFC 8292 VAPID).
//!
//! - **The VAPID key pair** is made once and kept in `<data>/console/vapid.key` (0600, in a 0700
//!   directory). Only its public half is ever shown (to signed-in sessions, which subscribe with it);
//!   the private key is never logged, and [`Vapid`]'s `Debug` prints the public key only.
//! - **Subscriptions** are kept per operator (the passkey that was signed in when the device
//!   subscribed) in `<data>/console/push-subscriptions.json` (0600): endpoint, the browser's `p256dh`
//!   and `auth` keys, when it was made and when a push last got through. A push service answering 404
//!   or 410 removes it. A passkey that is no longer enrolled gets no pushes. Registering a device and
//!   opting it in to details widen what it receives, so both are passkey-signed console actions
//!   (`push_subscribe`, `push_details` in `serve`); removing one or opting out need only the session.
//! - **Endpoints** must be HTTPS URLs on a known push service ([`PUSH_SERVICES`]); the console never
//!   sends to an arbitrary URL a client named (SSRF), and its client follows no redirects.
//! - **What is sent** ([`Notifier`]): one push per subscription for new requests, at most one per
//!   device per [`MIN_INTERVAL`] (new requests in between are coalesced into the next push), with a
//!   `Topic` so the push service keeps only the latest, `Urgency: high` and a TTL of [`TTL_SECS`].
//!   The payload says only how many requests are waiting and which one to open, since lock screens
//!   show it; a device that opts in also gets the agent and what it asks for.
//! - **Runs** ([`RunWatch`], #364): a push when an agent's turn ends (its run goes from busy to
//!   idle: it waits for its operator), and when a run ends (finished, or failed with its status's
//!   first word: `timeout`, `lost`, …). Not for a hibernation or a run another activation
//!   superseded. Under their own `Topic`, so they never replace a request's push, coalesced per
//!   device as requests are. A device gets none for a run whose session its operator has open in
//!   the console at that moment; when that can't be told, it gets the push (fail open). The payload
//!   names the run, and for a device that opted in the agent; never anything the agent said.
//!
//! The crypto is `p256` (ECDH and ES256, already used for passkeys) and `ring` (HKDF-SHA-256 and
//! AES-128-GCM, already in the tree through rustls), so Web Push adds no new crate.

use anyhow::{anyhow, bail, Context, Result};
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::sec1::ToSec1Point;
use ring::{aead, hkdf};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use wicket_auth::{b64u, unb64u};

/// How long a push service keeps a push it couldn't deliver yet (seconds).
pub const TTL_SECS: u32 = 3600;
/// At most one push per device this often (seconds); new requests in between are coalesced.
pub const MIN_INTERVAL: i64 = 30;
/// The `Topic` every push carries, so a push service holding undelivered pushes for a device keeps
/// only the latest. (Also the notification's tag, so the device shows one.)
pub const TOPIC: &str = "wicket-pending";
/// The `Topic` (and tag) of pushes about runs (#364).
pub const RUN_TOPIC: &str = "wicket-runs";
/// The push services the console sends to: (host, whether subdomains of it are meant instead).
pub const PUSH_SERVICES: &[(&str, bool)] =
    &[("fcm.googleapis.com", false), ("push.apple.com", true), ("updates.push.services.mozilla.com", false), ("notify.windows.com", true)];
/// RFC 8188 record size: one record, so the payload must fit in it.
const RECORD_SIZE: u32 = 4096;
const MAX_ENDPOINT: usize = 2048;
const MAX_LABEL: usize = 60;
pub const MAX_PER_OPERATOR: usize = 10;
pub const MAX_TOTAL: usize = 100;
/// A VAPID JWT's lifetime (RFC 8292 allows at most 24 hours).
const JWT_LIFETIME: i64 = 12 * 3600;
const _: () = assert!(JWT_LIFETIME <= 24 * 3600);
/// The longest request summary a details-on device gets.
const MAX_SUMMARY: usize = 200;

/// Checks that a subscription endpoint is an HTTPS URL on a known push service, and returns it.
pub fn check_endpoint(endpoint: &str) -> Result<url::Url> {
    if endpoint.len() > MAX_ENDPOINT {
        bail!("endpoint too long");
    }
    let u = url::Url::parse(endpoint).map_err(|_| anyhow!("endpoint is not a URL"))?;
    if u.scheme() != "https" {
        bail!("endpoint must be https");
    }
    if !u.username().is_empty() || u.password().is_some() || u.port().is_some() || u.fragment().is_some() {
        bail!("endpoint must be a plain https URL on the default port");
    }
    let Some(url::Host::Domain(host)) = u.host() else { bail!("endpoint must name a push service") };
    let host = host.to_ascii_lowercase();
    let known = PUSH_SERVICES.iter().any(|(d, sub)| {
        if !*sub {
            return host == *d;
        }
        host.strip_suffix(d).and_then(|p| p.strip_suffix('.')).is_some_and(|labels| {
            !labels.is_empty() && labels.split('.').all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        })
    });
    if !known {
        bail!("{host} is not a known push service");
    }
    Ok(u)
}

/// The console's VAPID key pair (RFC 8292).
pub struct Vapid {
    key: p256::ecdsa::SigningKey,
    public: Vec<u8>,
}

impl std::fmt::Debug for Vapid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vapid").field("public", &self.public_b64()).finish_non_exhaustive()
    }
}

fn random_secret() -> p256::SecretKey {
    loop {
        let mut b = [0u8; 32];
        getrandom::fill(&mut b).expect("OS randomness");
        if let Ok(k) = p256::SecretKey::from_slice(&b) {
            return k;
        }
    }
}

fn public_bytes(k: &p256::SecretKey) -> Vec<u8> {
    k.public_key().to_sec1_point(false).as_bytes().to_vec()
}

impl Vapid {
    fn from_secret(k: &p256::SecretKey) -> Vapid {
        Vapid { key: p256::ecdsa::SigningKey::from(k), public: public_bytes(k) }
    }

    /// Reads the key pair, or makes it (once) if the file doesn't exist.
    pub fn load_or_create(path: &Path) -> Result<Vapid> {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                let raw = unb64u(s.trim()).map_err(|_| anyhow!("{}: not a VAPID key", path.display()))?;
                let k = p256::SecretKey::from_slice(&raw).map_err(|_| anyhow!("{}: not a VAPID key", path.display()))?;
                Ok(Vapid::from_secret(&k))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let k = random_secret();
                super::acme::write_private(path, b64u(&k.to_bytes()).as_bytes())?;
                Ok(Vapid::from_secret(&k))
            }
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// The public key, uncompressed and base64url: the `applicationServerKey` browsers subscribe with.
    pub fn public_b64(&self) -> String {
        b64u(&self.public)
    }

    /// An ES256 JWT for one push service (`aud` its origin), until `exp`.
    pub fn jwt(&self, aud: &str, sub: &str, exp: i64) -> String {
        let head = b64u(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = b64u(json!({ "aud": aud, "exp": exp, "sub": sub }).to_string().as_bytes());
        let input = format!("{head}.{claims}");
        let sig: p256::ecdsa::Signature = self.key.sign(input.as_bytes());
        format!("{input}.{}", b64u(&sig.to_bytes()))
    }

    /// The `Authorization` header for a push to `endpoint` (RFC 8292 §3).
    pub fn authorization(&self, endpoint: &url::Url, sub: &str, now: i64) -> String {
        let aud = endpoint.origin().ascii_serialization();
        format!("vapid t={}, k={}", self.jwt(&aud, sub, now + JWT_LIFETIME), self.public_b64())
    }
}

/// HKDF-SHA-256: extract with `salt`, expand `info` to `len` bytes.
fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    struct Len(usize);
    impl hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(ikm);
    let mut out = vec![0u8; len];
    prk.expand(&[info], Len(len)).and_then(|okm| okm.fill(&mut out)).expect("HKDF output length");
    out
}

/// ECDH on P-256: the x coordinate of `secret · public`.
fn ecdh(secret: &p256::SecretKey, public: &p256::PublicKey) -> Vec<u8> {
    let shared = (public.to_projective() * *secret.to_nonzero_scalar()).to_affine();
    shared.to_sec1_point(false).x().expect("not the identity").to_vec()
}

/// Encrypts a push message for a browser (RFC 8291, `aes128gcm` content coding of RFC 8188): one
/// record, with the application server's ephemeral key `as_secret` and a random `salt`.
pub fn encrypt(ua_public: &[u8], auth: &[u8], plaintext: &[u8], as_secret: &p256::SecretKey, salt: &[u8; 16]) -> Result<Vec<u8>> {
    if ua_public.len() != 65 || auth.len() != 16 {
        bail!("bad subscription keys");
    }
    let ua = p256::PublicKey::from_sec1_bytes(ua_public).map_err(|_| anyhow!("p256dh is not a P-256 point"))?;
    let as_public = public_bytes(as_secret);
    let mut key_info = b"WebPush: info\0".to_vec();
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(&as_public);
    let ikm = hkdf(auth, &ecdh(as_secret, &ua), &key_info, 32);
    let cek = hkdf(salt, &ikm, b"Content-Encoding: aes128gcm\0", 16);
    let nonce = hkdf(salt, &ikm, b"Content-Encoding: nonce\0", 12);
    let mut record = plaintext.to_vec();
    record.push(2); // the last (and only) record's delimiter, no padding
    if record.len() + 16 > RECORD_SIZE as usize - 86 {
        bail!("push payload too large");
    }
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &cek).expect("AES-128 key"));
    let nonce = aead::Nonce::try_assume_unique_for_key(&nonce).expect("96-bit nonce");
    key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut record).map_err(|_| anyhow!("encryption failed"))?;
    let mut out = Vec::with_capacity(86 + record.len());
    out.extend_from_slice(salt);
    out.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    out.push(as_public.len() as u8);
    out.extend_from_slice(&as_public);
    out.extend_from_slice(&record);
    Ok(out)
}

/// A device's push subscription.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Subscription {
    /// The first 16 hex digits of the endpoint's SHA-256 (the endpoint itself is a capability).
    pub id: String,
    /// The passkey (credential id) signed in when the device subscribed.
    pub operator: String,
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
    pub label: String,
    /// Opted in to the agent and what it asks for in the notification.
    pub details: bool,
    pub created: i64,
    pub last_success: Option<i64>,
}

impl Subscription {
    /// Checks a subscription as a browser posts it (a known push service, a P-256 key, a 16-byte
    /// secret) and makes it `operator`'s. Nothing is stored.
    pub fn new(operator: &str, d: &NewDevice, now: i64) -> Result<Subscription> {
        let NewDevice { endpoint, p256dh, auth, label, details } = *d;
        check_endpoint(endpoint)?;
        let key = unb64u(p256dh).map_err(|_| anyhow!("p256dh must be base64url"))?;
        if key.len() != 65 || p256::PublicKey::from_sec1_bytes(&key).is_err() {
            bail!("p256dh must be an uncompressed P-256 public key");
        }
        if unb64u(auth).map(|a| a.len()) != Ok(16) {
            bail!("auth must be 16 bytes, base64url");
        }
        let label: String = wicket_core::text::strip(label).trim().chars().take(MAX_LABEL).collect();
        Ok(Subscription {
            id: subscription_id(endpoint),
            operator: operator.to_string(),
            endpoint: endpoint.to_string(),
            p256dh: b64u(&key),
            auth: auth.trim_end_matches('=').to_string(),
            label: if label.is_empty() { "device".into() } else { label },
            details,
            created: now,
            last_success: None,
        })
    }

    /// What the console shows of it: never the endpoint or keys.
    pub fn view(&self) -> Value {
        let host = url::Url::parse(&self.endpoint).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_default();
        json!({ "id": self.id, "label": self.label, "service": host, "details": self.details,
                "created": self.created, "last_success": self.last_success })
    }
}

pub fn subscription_id(endpoint: &str) -> String {
    hex::encode(sha2::Sha256::digest(endpoint.as_bytes()))[..16].to_string()
}

/// A subscription as a browser posts it.
#[derive(Clone, Copy, Debug)]
pub struct NewDevice<'a> {
    pub endpoint: &'a str,
    pub p256dh: &'a str,
    pub auth: &'a str,
    pub label: &'a str,
    pub details: bool,
}

/// The subscriptions, in a 0600 JSON file.
pub struct Store {
    path: PathBuf,
    subs: Mutex<Vec<Subscription>>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        let subs = match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).with_context(|| format!("reading {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Store { path: path.to_path_buf(), subs: Mutex::new(subs) })
    }

    fn save(&self, subs: &[Subscription]) -> Result<()> {
        super::acme::write_private(&self.path, &serde_json::to_vec_pretty(subs)?)
    }

    /// Adds (or replaces, by endpoint) a subscription for `operator`. The console registers devices
    /// only through a signed action ([`Store::insert`]); tests add them directly.
    #[cfg(test)]
    pub fn add(&self, operator: &str, d: &NewDevice, now: i64) -> Result<Subscription> {
        self.insert(Subscription::new(operator, d, now)?)
    }

    /// Adds (or replaces, by endpoint) a subscription already checked by [`Subscription::new`].
    pub fn insert(&self, sub: Subscription) -> Result<Subscription> {
        let (operator, endpoint) = (sub.operator.as_str(), sub.endpoint.as_str());
        let mut subs = self.subs.lock().expect("lock");
        let mut next: Vec<Subscription> = subs.iter().filter(|s| s.endpoint != endpoint).cloned().collect();
        if next.iter().filter(|s| s.operator == operator).count() >= MAX_PER_OPERATOR {
            bail!("at most {MAX_PER_OPERATOR} devices per passkey: remove one first");
        }
        if next.len() >= MAX_TOTAL {
            bail!("at most {MAX_TOTAL} devices: remove one first");
        }
        next.push(sub.clone());
        self.save(&next)?;
        *subs = next;
        Ok(sub)
    }

    fn update(&self, f: impl FnOnce(&mut Vec<Subscription>) -> bool) -> Result<bool> {
        let mut subs = self.subs.lock().expect("lock");
        let mut next = subs.clone();
        if !f(&mut next) {
            return Ok(false);
        }
        self.save(&next)?;
        *subs = next;
        Ok(true)
    }

    /// Removes one of `operator`'s subscriptions. False if it has none by that id.
    pub fn remove(&self, operator: &str, id: &str) -> Result<bool> {
        self.update(|v| {
            let n = v.len();
            v.retain(|s| !(s.operator == operator && s.id == id));
            v.len() != n
        })
    }

    pub fn set_details(&self, operator: &str, id: &str, details: bool) -> Result<bool> {
        self.update(|v| match v.iter_mut().find(|s| s.operator == operator && s.id == id) {
            Some(s) => {
                s.details = details;
                true
            }
            None => false,
        })
    }

    pub fn list(&self, operator: &str) -> Vec<Subscription> {
        self.subs.lock().expect("lock").iter().filter(|s| s.operator == operator).cloned().collect()
    }

    pub fn all(&self) -> Vec<Subscription> {
        self.subs.lock().expect("lock").clone()
    }

    /// Records what the push service said to a push: 2xx is a success, 404 or 410 means the
    /// subscription is gone (it is removed). Returns whether it was removed.
    pub fn record(&self, id: &str, status: u16, now: i64) -> Result<bool> {
        match status {
            200..=299 => {
                self.update(|v| match v.iter_mut().find(|s| s.id == id) {
                    Some(s) => {
                        s.last_success = Some(now);
                        true
                    }
                    None => false,
                })?;
                Ok(false)
            }
            404 | 410 => self.update(|v| {
                let n = v.len();
                v.retain(|s| s.id != id);
                v.len() != n
            }),
            _ => Ok(false),
        }
    }
}

/// A request that is waiting, as the notifier sees it.
#[derive(Clone, Debug)]
pub struct Waiting {
    pub id: String,
    /// The agent and what it asks for (only for devices that opted in).
    pub summary: String,
}

/// A push to send: to whom, and the plaintext payload (JSON).
#[derive(Clone, Debug)]
pub struct Outgoing {
    pub sub: Subscription,
    pub payload: Vec<u8>,
    /// The push's `Topic`: [`TOPIC`] or [`RUN_TOPIC`].
    pub topic: &'static str,
}

/// Decides which pushes to send, from successive looks at what is waiting. Requests already waiting
/// at its first look are not announced (a restarted console doesn't repeat itself).
#[derive(Default)]
pub struct Notifier {
    seen: Option<HashSet<String>>,
    /// Subscriptions owed a push, with the newest new request to open.
    owed: HashMap<String, String>,
    last_sent: HashMap<String, i64>,
    /// Run changes owed to each subscription, and when it last got one (#364).
    owed_runs: HashMap<String, Vec<RunNote>>,
    last_run_sent: HashMap<String, i64>,
    pub runs: RunWatch,
}

pub fn payload(waiting: &[Waiting], open: &Waiting, details: bool) -> Vec<u8> {
    let n = waiting.len();
    let mut body = if n == 1 { "1 request waiting".to_string() } else { format!("{n} requests waiting") };
    if details {
        body = format!("{body}: {}", wicket_core::text::clip(&open.summary, MAX_SUMMARY));
    }
    json!({ "title": "wicket", "body": body, "id": open.id, "count": n, "tag": TOPIC }).to_string().into_bytes()
}

impl Notifier {
    pub fn tick(&mut self, waiting: &[Waiting], subs: &[Subscription], now: i64) -> Vec<Outgoing> {
        let ids: HashSet<String> = waiting.iter().map(|w| w.id.clone()).collect();
        let newest = match &self.seen {
            None => None,
            Some(seen) => waiting.iter().rev().find(|w| !seen.contains(&w.id)).map(|w| w.id.clone()),
        };
        self.seen = Some(ids);
        if let Some(n) = newest {
            for s in subs {
                self.owed.insert(s.id.clone(), n.clone());
            }
        }
        self.owed.retain(|id, _| subs.iter().any(|s| &s.id == id));
        self.last_sent.retain(|id, t| now - *t < MIN_INTERVAL && subs.iter().any(|s| &s.id == id));
        let Some(last) = waiting.last() else {
            self.owed.clear();
            return Vec::new();
        };
        let mut out = Vec::new();
        for s in subs {
            let Some(rid) = self.owed.get(&s.id) else { continue };
            if self.last_sent.contains_key(&s.id) {
                continue; // sent less than MIN_INTERVAL ago: coalesced into the next one
            }
            let open = waiting.iter().find(|w| &w.id == rid).unwrap_or(last);
            out.push(Outgoing { sub: s.clone(), payload: payload(waiting, open, s.details), topic: TOPIC });
            self.owed.remove(&s.id);
            self.last_sent.insert(s.id.clone(), now);
        }
        out
    }
}

/// What happened to a run that its operator may want to know (#364).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunEvent {
    /// A turn ended: the agent waits for its operator.
    TurnDone,
    Finished,
    /// Ended otherwise: its status's first word.
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunNote {
    pub run: String,
    pub agent: String,
    pub event: RunEvent,
}

/// Run state changes between successive looks at the ledger's runs. What it sees at its first look
/// is not announced, as for requests.
#[derive(Default)]
pub struct RunWatch {
    seen: Option<HashMap<String, (String, Option<String>)>>,
}

impl RunWatch {
    pub fn changes(&mut self, runs: &[wicket_store::RunState]) -> Vec<RunNote> {
        let now: HashMap<String, (String, Option<String>)> =
            runs.iter().map(|r| (r.id.clone(), (r.status.clone(), r.activity.clone()))).collect();
        let Some(seen) = self.seen.replace(now) else { return vec![] };
        let mut out = vec![];
        for r in runs {
            let Some((was, was_activity)) = seen.get(&r.id) else { continue };
            let event = if was == "running" && r.status != "running" {
                match r.status.split([' ', '(']).next().unwrap_or("") {
                    "succeeded" => Some(RunEvent::Finished),
                    "hibernated" | "superseded" | "" => None,
                    word => Some(RunEvent::Failed(wicket_core::text::clip(word, 20))),
                }
            } else if r.status == "running" && was_activity.as_deref() == Some("busy") && r.activity.as_deref() == Some("idle") {
                Some(RunEvent::TurnDone)
            } else {
                None
            };
            if let Some(event) = event {
                out.push(RunNote { run: r.id.clone(), agent: r.agent.clone(), event });
            }
        }
        out
    }
}

/// A run push's payload: what happened (the agent only for a device that opted in), and the run
/// to open.
pub fn run_payload(notes: &[RunNote], details: bool) -> Vec<u8> {
    let last = notes.last().expect("a note");
    let who = if details { format!("{}: ", wicket_core::text::clip(&last.agent, MAX_LABEL)) } else { String::new() };
    let what = match &last.event {
        RunEvent::TurnDone => "the agent's turn ended".to_string(),
        RunEvent::Finished => "a run finished".to_string(),
        RunEvent::Failed(w) => format!("a run ended ({w})"),
    };
    let more = if notes.len() > 1 { format!(" (and {} more)", notes.len() - 1) } else { String::new() };
    json!({ "title": "wicket", "body": format!("{who}{what}{more}"), "run": last.run, "count": notes.len(), "tag": RUN_TOPIC })
        .to_string()
        .into_bytes()
}

impl Notifier {
    /// Pushes for run changes, per device: at most one per [`MIN_INTERVAL`] (notes in between are
    /// coalesced), none about a run `watching(device, run)` says its operator watches now.
    pub fn tick_runs(
        &mut self,
        notes: &[RunNote],
        subs: &[Subscription],
        watching: &dyn Fn(&Subscription, &str) -> bool,
        now: i64,
    ) -> Vec<Outgoing> {
        for s in subs {
            let owed = self.owed_runs.entry(s.id.clone()).or_default();
            owed.extend(notes.iter().cloned());
            let n = owed.len();
            if n > 32 {
                owed.drain(..n - 32);
            }
        }
        self.owed_runs.retain(|id, _| subs.iter().any(|s| &s.id == id));
        self.last_run_sent.retain(|id, t| now - *t < MIN_INTERVAL && subs.iter().any(|s| &s.id == id));
        let mut out = vec![];
        for s in subs {
            if self.last_run_sent.contains_key(&s.id) {
                continue;
            }
            let Some(owed) = self.owed_runs.get_mut(&s.id) else { continue };
            owed.retain(|n| !watching(s, &n.run));
            if owed.is_empty() {
                continue;
            }
            out.push(Outgoing { sub: s.clone(), payload: run_payload(owed, s.details), topic: RUN_TOPIC });
            owed.clear();
            self.last_run_sent.insert(s.id.clone(), now);
        }
        out
    }
}

/// An encrypted push, ready to POST.
#[derive(Clone, Debug)]
pub struct PushRequest {
    pub url: url::Url,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

/// `topic` is [`TOPIC`] (a request waiting: urgent) or [`RUN_TOPIC`] (normal urgency).
pub fn build_request(vapid: &Vapid, sub: &Subscription, plaintext: &[u8], topic: &str, contact: &str, now: i64) -> Result<PushRequest> {
    let url = check_endpoint(&sub.endpoint)?;
    let ua = unb64u(&sub.p256dh).map_err(|_| anyhow!("bad p256dh"))?;
    let auth = unb64u(&sub.auth).map_err(|_| anyhow!("bad auth"))?;
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).expect("OS randomness");
    let body = encrypt(&ua, &auth, plaintext, &random_secret(), &salt)?;
    let headers = vec![
        ("authorization", vapid.authorization(&url, contact, now)),
        ("content-encoding", "aes128gcm".to_string()),
        ("content-type", "application/octet-stream".to_string()),
        ("ttl", TTL_SECS.to_string()),
        ("urgency", if topic == TOPIC { "high" } else { "normal" }.to_string()),
        ("topic", topic.to_string()),
    ];
    Ok(PushRequest { url, headers, body })
}

/// Sends a push and returns the push service's status. The real one is reqwest (HTTPS only, no
/// redirects); tests record instead.
pub type Transport = Arc<dyn Fn(PushRequest) -> futures_util::future::BoxFuture<'static, Result<u16>> + Send + Sync>;

pub fn reqwest_transport() -> Transport {
    let client = reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .expect("reqwest client");
    Arc::new(move |p: PushRequest| {
        let client = client.clone();
        Box::pin(async move {
            let mut r = client.post(p.url);
            for (k, v) in p.headers {
                r = r.header(k, v);
            }
            Ok(r.body(p.body).send().await?.status().as_u16())
        })
    })
}

/// Push state for the console: the key pair, the subscriptions, and how pushes are sent.
pub struct Push {
    pub vapid: Vapid,
    pub store: Store,
    pub transport: Transport,
    /// The VAPID `sub` claim: the console's origin when HTTPS (else a mailto placeholder).
    pub contact: String,
}

impl Push {
    pub fn open(dir: &Path, origin: &str, transport: Transport) -> Result<Push> {
        let vapid = Vapid::load_or_create(&dir.join("vapid.key"))?;
        let store = Store::open(&dir.join("push-subscriptions.json"))?;
        let contact = if origin.starts_with("https://") { origin.to_string() } else { "mailto:operator@localhost".to_string() };
        Ok(Push { vapid, store, transport, contact })
    }

    /// Sends the pushes, recording each result (and removing subscriptions the service says are gone).
    pub async fn deliver(&self, out: Vec<Outgoing>, now: i64) -> Vec<(String, u16)> {
        let mut results = Vec::new();
        for o in out {
            let host = url::Url::parse(&o.sub.endpoint).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_default();
            let req = match build_request(&self.vapid, &o.sub, &o.payload, o.topic, &self.contact, now) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("push to device {} ({host}) not sent: {e:#}", o.sub.id);
                    continue;
                }
            };
            match (self.transport)(req).await {
                Ok(status) => {
                    match self.store.record(&o.sub.id, status, now) {
                        Ok(true) => tracing::info!("push device {} ({host}) is gone ({status}): removed", o.sub.id),
                        Ok(false) if !(200..300).contains(&status) => tracing::warn!("push to device {} ({host}): HTTP {status}", o.sub.id),
                        Ok(false) => {}
                        Err(e) => tracing::warn!("push subscriptions not saved: {e:#}"),
                    }
                    results.push((o.sub.id.clone(), status));
                }
                Err(e) => tracing::warn!("push to device {} ({host}) failed: {e:#}", o.sub.id),
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    fn d(s: &str) -> Vec<u8> {
        unb64u(s).unwrap()
    }

    /// RFC 8291 appendix A, every value as the RFC gives it.
    #[test]
    fn rfc8291_test_vector() {
        let plaintext = b"When I grow up, I want to be a watermelon";
        let as_secret = p256::SecretKey::from_slice(&d("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")).unwrap();
        assert_eq!(
            b64u(&public_bytes(&as_secret)),
            "BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8"
        );
        let ua_secret = p256::SecretKey::from_slice(&d("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")).unwrap();
        let ua_public = d("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4");
        assert_eq!(public_bytes(&ua_secret), ua_public);
        let shared = ecdh(&as_secret, &p256::PublicKey::from_sec1_bytes(&ua_public).unwrap());
        assert_eq!(b64u(&shared), "kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs");
        assert_eq!(shared, ecdh(&ua_secret, &as_secret.public_key()));
        let auth = d("BTBZMqHH6r4Tts7J_aSIgg");
        let salt: [u8; 16] = d("DGv6ra1nlYgDCS1FRnbzlw").try_into().unwrap();
        let mut key_info = b"WebPush: info\0".to_vec();
        key_info.extend_from_slice(&ua_public);
        key_info.extend_from_slice(&public_bytes(&as_secret));
        let ikm = hkdf(&auth, &shared, &key_info, 32);
        assert_eq!(b64u(&ikm), "S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg");
        assert_eq!(b64u(&hkdf(&salt, &ikm, b"Content-Encoding: aes128gcm\0", 16)), "oIhVW04MRdy2XN9CiKLxTg");
        assert_eq!(b64u(&hkdf(&salt, &ikm, b"Content-Encoding: nonce\0", 12)), "4h_95klXJ5E_qnoN");
        let msg = encrypt(&ua_public, &auth, plaintext, &as_secret, &salt).unwrap();
        assert_eq!(
            b64u(&msg),
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
        );
        // Wrong-size keys and payloads that don't fit one record are refused.
        assert!(encrypt(&ua_public[..64], &auth, plaintext, &as_secret, &salt).is_err());
        assert!(encrypt(&ua_public, &auth[..15], plaintext, &as_secret, &salt).is_err());
        assert!(encrypt(&ua_public, &auth, &[b'x'; 4000], &as_secret, &salt).is_err());
    }

    #[test]
    fn vapid_jwt_shape_and_signature() {
        let dir = super::super::tests::TmpDir::new("vapid");
        let path = dir.0.join("console/vapid.key");
        let v = Vapid::load_or_create(&path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
        // Made once: the same key next time.
        assert_eq!(Vapid::load_or_create(&path).unwrap().public_b64(), v.public_b64());
        assert!(!format!("{v:?}").contains(std::fs::read_to_string(&path).unwrap().trim()), "Debug never shows the private key");
        let pk = d(&v.public_b64());
        assert_eq!((pk.len(), pk[0]), (65, 4));

        let ep = url::Url::parse("https://fcm.googleapis.com/fcm/send/abc").unwrap();
        let h = v.authorization(&ep, "https://console.example", 1_000);
        let (t, k) = h.strip_prefix("vapid t=").unwrap().split_once(", k=").unwrap();
        assert_eq!(k, v.public_b64());
        let parts: Vec<&str> = t.split('.').collect();
        assert_eq!(parts.len(), 3);
        let head: Value = serde_json::from_slice(&d(parts[0])).unwrap();
        assert_eq!(head, json!({ "typ": "JWT", "alg": "ES256" }));
        let claims: Value = serde_json::from_slice(&d(parts[1])).unwrap();
        assert_eq!(claims, json!({ "aud": "https://fcm.googleapis.com", "exp": 1_000 + JWT_LIFETIME, "sub": "https://console.example" }));
        let sig = d(parts[2]);
        assert_eq!(sig.len(), 64, "ES256 is r || s, not DER");
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&pk).unwrap();
        let sig = p256::ecdsa::Signature::from_slice(&sig).unwrap();
        vk.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).unwrap();
        assert!(vk.verify(format!("{}.{}x", parts[0], parts[1]).as_bytes(), &sig).is_err());
    }

    #[test]
    fn only_known_push_services_are_endpoints() {
        for ok in [
            "https://fcm.googleapis.com/fcm/send/abc:def",
            "https://web.push.apple.com/QGh1dGxpbmc",
            "https://api.push.apple.com/3/device/x",
            "https://updates.push.services.mozilla.com/wpush/v2/gAAAA",
            "https://wns2-par02p.notify.windows.com/w/?token=BQYAAA",
            "https://FCM.googleapis.com/fcm/send/x",
            "https://fcm.googleapis.com:443/fcm/send/x",
        ] {
            assert!(check_endpoint(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://fcm.googleapis.com/fcm/send/x",
            "https://fcm.googleapis.com:8443/x",
            "https://user@fcm.googleapis.com/x",
            "https://fcm.googleapis.com.evil.com/x",
            "https://evilfcm.googleapis.com/x",
            "https://push.apple.com/x",
            "https://evilpush.apple.com/x",
            "https://notify.windows.com/x",
            "https://x.notify.windows.com.evil/x",
            "https://127.0.0.1/x",
            "https://[::1]/x",
            "https://localhost/x",
            "https://169.254.169.254/latest/meta-data",
            "https://metadata.google.internal/x",
            "https://fcm.googleapis.com/x#frag",
            "file:///etc/passwd",
            "not a url",
        ] {
            assert!(check_endpoint(bad).is_err(), "{bad}");
        }
        assert!(check_endpoint(&format!("https://fcm.googleapis.com/{}", "a".repeat(MAX_ENDPOINT))).is_err());
    }

    pub(crate) fn browser_keys() -> (String, String) {
        (b64u(&public_bytes(&random_secret())), b64u(&[7u8; 16]))
    }

    #[test]
    fn subscriptions_are_stored_per_operator_and_removed_when_gone() {
        let dir = super::super::tests::TmpDir::new("pushstore");
        let path = dir.0.join("console/push-subscriptions.json");
        let s = Store::open(&path).unwrap();
        let (p, a) = browser_keys();
        let one = s
            .add(
                "cred-a",
                &NewDevice {
                    endpoint: "https://fcm.googleapis.com/fcm/send/1",
                    p256dh: &p,
                    auth: &a,
                    label: "phone\u{202e}",
                    details: false,
                },
                10,
            )
            .unwrap();
        assert_eq!(one.label, "phone");
        let two = s
            .add("cred-b", &NewDevice { endpoint: "https://web.push.apple.com/2", p256dh: &p, auth: &a, label: "", details: true }, 11)
            .unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(s.list("cred-a"), vec![one.clone()]);
        assert!(!one.view().to_string().contains("fcm/send/1"), "the view never shows the endpoint");
        // Bad keys, unknown services.
        assert!(s
            .add("cred-a", &NewDevice { endpoint: "https://evil.example/x", p256dh: &p, auth: &a, label: "", details: false }, 12)
            .is_err());
        assert!(s
            .add("cred-a", &NewDevice { endpoint: "https://fcm.googleapis.com/x", p256dh: "AAAA", auth: &a, label: "", details: false }, 12)
            .is_err());
        assert!(s
            .add("cred-a", &NewDevice { endpoint: "https://fcm.googleapis.com/x", p256dh: &p, auth: "AAAA", label: "", details: false }, 12)
            .is_err());
        // Another operator can't remove or change it.
        assert!(!s.remove("cred-b", &one.id).unwrap());
        assert!(!s.set_details("cred-b", &one.id, true).unwrap());
        assert!(s.set_details("cred-a", &one.id, true).unwrap());
        // It survives a restart, with what the push service said.
        s.record(&one.id, 201, 20).unwrap();
        let s = Store::open(&path).unwrap();
        let got = s.list("cred-a");
        assert_eq!((got[0].details, got[0].last_success), (true, Some(20)));
        // 410 and 404 remove it; other failures don't.
        assert!(!s.record(&one.id, 500, 21).unwrap());
        assert!(!s.record(&one.id, 429, 21).unwrap());
        assert!(s.record(&one.id, 410, 22).unwrap());
        assert!(s.record(&two.id, 404, 22).unwrap());
        assert!(Store::open(&path).unwrap().all().is_empty());
        // Bounded per operator.
        for i in 0..MAX_PER_OPERATOR {
            s.add(
                "cred-a",
                &NewDevice {
                    endpoint: &format!("https://fcm.googleapis.com/fcm/send/{i}"),
                    p256dh: &p,
                    auth: &a,
                    label: "",
                    details: false,
                },
                30,
            )
            .unwrap();
        }
        assert!(s
            .add(
                "cred-a",
                &NewDevice { endpoint: "https://fcm.googleapis.com/fcm/send/more", p256dh: &p, auth: &a, label: "", details: false },
                30
            )
            .is_err());
        // Re-subscribing the same endpoint replaces it.
        s.add(
            "cred-a",
            &NewDevice { endpoint: "https://fcm.googleapis.com/fcm/send/0", p256dh: &p, auth: &a, label: "", details: true },
            31,
        )
        .unwrap();
        assert_eq!(s.list("cred-a").len(), MAX_PER_OPERATOR);
    }

    fn w(id: &str) -> Waiting {
        Waiting { id: id.into(), summary: format!("agent-{id}: GET api.example.com/{id}") }
    }

    fn sub(id: &str, details: bool) -> Subscription {
        Subscription {
            id: id.into(),
            operator: "c".into(),
            endpoint: format!("https://fcm.googleapis.com/fcm/send/{id}"),
            p256dh: String::new(),
            auth: String::new(),
            label: String::new(),
            details,
            created: 0,
            last_success: None,
        }
    }

    fn body(o: &Outgoing) -> Value {
        serde_json::from_slice(&o.payload).unwrap()
    }

    #[test]
    fn one_push_per_new_request_coalesced_per_device() {
        let mut n = Notifier::default();
        let subs = vec![sub("s1", false), sub("s2", true)];
        // What was already waiting at start isn't announced.
        assert!(n.tick(&[w("r-1")], &subs, 0).is_empty());
        assert!(n.tick(&[w("r-1")], &subs, 3).is_empty());
        // A new request: one push per subscription.
        let out = n.tick(&[w("r-1"), w("r-2")], &subs, 6);
        assert_eq!(out.len(), 2);
        assert_eq!(body(&out[0]), json!({ "title": "wicket", "body": "2 requests waiting", "id": "r-2", "count": 2, "tag": TOPIC }));
        assert_eq!(body(&out[1])["body"], "2 requests waiting: agent-r-2: GET api.example.com/r-2");
        // Seen again: nothing.
        assert!(n.tick(&[w("r-1"), w("r-2")], &subs, 9).is_empty());
        // Two more within 30 s: coalesced, sent once when the interval has passed.
        assert!(n.tick(&[w("r-1"), w("r-2"), w("r-3")], &subs, 12).is_empty());
        assert!(n.tick(&[w("r-1"), w("r-2"), w("r-3"), w("r-4")], &subs, 20).is_empty());
        assert!(n.tick(&[w("r-1"), w("r-2"), w("r-3"), w("r-4")], &subs, 35).is_empty());
        let out = n.tick(&[w("r-1"), w("r-2"), w("r-3"), w("r-4")], &subs, 36);
        assert_eq!(out.len(), 2);
        assert_eq!((body(&out[0])["body"].as_str().unwrap(), body(&out[0])["id"].as_str().unwrap()), ("4 requests waiting", "r-4"));
        assert!(n.tick(&[w("r-1"), w("r-2"), w("r-3"), w("r-4")], &subs, 100).is_empty());
        // Owed, then everything decided before it was due: nothing to say.
        n.tick(&[w("r-5")], &subs, 110);
        assert!(n.tick(&[w("r-6")], &subs, 115).is_empty());
        assert!(n.tick(&[], &subs, 150).is_empty());
        // The request to open was decided meanwhile: open the newest still waiting.
        n.tick(&[w("r-7")], &subs, 200);
        n.tick(&[w("r-7"), w("r-8")], &subs, 210);
        let out = n.tick(&[w("r-7")], &subs, 240);
        assert_eq!(body(&out[0])["id"], "r-7");
        // A device that subscribes later is owed only what is new after it did.
        let more = vec![sub("s1", false), sub("s2", true), sub("s3", false)];
        assert!(n.tick(&[w("r-7")], &more, 300).is_empty());
        let out = n.tick(&[w("r-7"), w("r-9")], &more, 303);
        assert_eq!(out.iter().map(|o| o.sub.id.as_str()).collect::<Vec<_>>(), ["s1", "s2", "s3"]);
    }

    #[tokio::test]
    async fn deliver_encrypts_sets_the_headers_and_drops_gone_subscriptions() {
        let dir = super::super::tests::TmpDir::new("pushdeliver");
        let sent: Arc<Mutex<Vec<PushRequest>>> = Arc::default();
        let log = sent.clone();
        let transport: Transport = Arc::new(move |p: PushRequest| {
            let status = if p.url.as_str().contains("gone") { 410 } else { 201 };
            log.lock().unwrap().push(p);
            Box::pin(async move { Ok(status) })
        });
        let push = Push::open(&dir.0.join("console"), "https://console.example", transport).unwrap();
        let ua = random_secret();
        let (p, a) = (b64u(&public_bytes(&ua)), b64u(&[9u8; 16]));
        let live = push
            .store
            .add(
                "c",
                &NewDevice { endpoint: "https://fcm.googleapis.com/fcm/send/live", p256dh: &p, auth: &a, label: "laptop", details: false },
                1,
            )
            .unwrap();
        push.store
            .add("c", &NewDevice { endpoint: "https://web.push.apple.com/gone", p256dh: &p, auth: &a, label: "phone", details: false }, 1)
            .unwrap();
        let mut n = Notifier::default();
        n.tick(&[], &push.store.all(), 0);
        let out = n.tick(&[w("r-1")], &push.store.all(), 5);
        let results = push.deliver(out, 5).await;
        assert_eq!(results.len(), 2);
        assert_eq!(push.store.all().iter().map(|s| (s.id.clone(), s.last_success)).collect::<Vec<_>>(), vec![(live.id.clone(), Some(5))]);
        let sent = sent.lock().unwrap();
        let r = &sent[0];
        let h: HashMap<&str, &str> = r.headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        assert_eq!((h["content-encoding"], h["ttl"], h["urgency"], h["topic"]), ("aes128gcm", "3600", "high", TOPIC));
        assert!(h["authorization"].starts_with("vapid t=") && h["authorization"].ends_with(&format!(", k={}", push.vapid.public_b64())));
        // The body is the payload, encrypted for the device: decrypt it as a browser would.
        let b = &r.body;
        let (salt, idlen) = (&b[..16], b[20] as usize);
        assert_eq!(u32::from_be_bytes(b[16..20].try_into().unwrap()), RECORD_SIZE);
        let as_public = p256::PublicKey::from_sec1_bytes(&b[21..21 + idlen]).unwrap();
        let mut key_info = b"WebPush: info\0".to_vec();
        key_info.extend_from_slice(&public_bytes(&ua));
        key_info.extend_from_slice(&b[21..21 + idlen]);
        let ikm = hkdf(&[9u8; 16], &ecdh(&ua, &as_public), &key_info, 32);
        let cek = hkdf(salt, &ikm, b"Content-Encoding: aes128gcm\0", 16);
        let nonce = hkdf(salt, &ikm, b"Content-Encoding: nonce\0", 12);
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &cek).unwrap());
        let mut rec = b[21 + idlen..].to_vec();
        let plain = key.open_in_place(aead::Nonce::try_assume_unique_for_key(&nonce).unwrap(), aead::Aad::empty(), &mut rec).unwrap();
        assert_eq!(plain.last(), Some(&2));
        let v: Value = serde_json::from_slice(&plain[..plain.len() - 1]).unwrap();
        assert_eq!(v["body"], "1 request waiting");
        assert_eq!(v["id"], "r-1");
    }
}
