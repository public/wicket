//! `wicket node intake` (#578 step 4; docs/explanation/trigger-intake.md): webhook intake, a small
//! service of its own on a node, beside its `wicket node serve`.
//!
//! It holds no ledger, no vault, no authority and no files. It knows the triggers it serves (their
//! token's sha256, verify secret, and for GitHub the repository and events) from its `node serve`,
//! over the node's intake socket, every [`TABLE_EVERY`]. It faces the internet, so:
//! - the server is bounded as the console's is: a connection cap, a per-address cap, a header
//!   timeout, a lifetime, header limits ([`limits`]);
//! - the path and token are checked before any of the body is read, and an address that keeps
//!   failing is slowed down before it costs more ([`Intake::admit`]);
//! - the body is capped, then its signature checked, and only a verified delivery counts against
//!   its trigger's rate ([`Intake::verify`]);
//! - it is normalised into a capped set of fields (`wicket_core::intake`) and handed to `node
//!   serve`, which spools it until the control host takes it.
//!
//! The answer is a status and a fixed word: never anything of the payload.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use wicket_core::intake::{self as ik, IntakeEvent, IntakeRefused, IntakeTrigger};

/// How often the table is fetched again (and refusals reported).
pub const TABLE_EVERY: Duration = Duration::from_secs(10);
/// A trigger's verified deliveries: a token bucket of this many a minute …
pub const PER_TRIGGER_PER_MIN: f64 = 60.0;
/// … with this burst.
pub const PER_TRIGGER_BURST: f64 = 20.0;
/// Every trigger's verified deliveries together.
pub const ALL_PER_MIN: f64 = 600.0;
pub const ALL_BURST: f64 = 100.0;
/// An address's failures (unknown path or token, bad signature): past this it is answered 429
/// before anything else is looked at.
pub const FAILURES_PER_MIN: f64 = 30.0;
pub const FAILURES_BURST: f64 = 10.0;
/// The most addresses whose failures are remembered (oldest forgotten first).
const FAILURE_ADDRESSES: usize = 4096;

/// The server's bounds: the console's, with intake's body cap and its own connection counts.
pub fn limits() -> crate::serve::net::Limits {
    crate::serve::net::Limits {
        handshake_timeout: Duration::from_secs(10),
        header_timeout: Duration::from_secs(10),
        body_timeout: Duration::from_secs(30),
        conn_lifetime: Duration::from_secs(60),
        max_header_bytes: 16 * 1024,
        max_headers: 64,
        max_body: ik::MAX_BODY,
        max_connections: 256,
        per_ip_connections: 16,
    }
}

struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn full(burst: f64, at: Instant) -> Bucket {
        Bucket { tokens: burst, at }
    }

    fn fill(&mut self, per_min: f64, burst: f64, now: Instant) {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + dt * per_min / 60.0).min(burst);
        self.at = now;
    }

    fn take(&mut self, per_min: f64, burst: f64, now: Instant) -> bool {
        self.fill(per_min, burst, now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Whether a token is left, without taking it.
    fn has(&mut self, per_min: f64, burst: f64, now: Instant) -> bool {
        self.fill(per_min, burst, now);
        self.tokens >= 1.0
    }
}

/// What intake decided about one delivery.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// Verified: spool this, then answer 202.
    Spool(Box<IntakeEvent>),
    /// Answer this, with this word.
    Answer(StatusCode, &'static str),
}

/// How long intake remembers a delivery it handed to its node (its body's hash and its id), to
/// answer one sent again 202 without spooling it or charging its trigger (#714 review F2).
pub const SEEN_SECS: u64 = 86_400;
/// The most deliveries remembered (the oldest forgotten first).
const SEEN_MAX: usize = 20_000;

/// Intake's state: the table, the rate buckets, what it has recently handed over, and the
/// refusals not yet reported.
pub struct Intake {
    table: RwLock<Vec<IntakeTrigger>>,
    /// Whether `node serve` has had the control host's table since it started: until then, every
    /// delivery is answered 503 (try later), not 404 (#714 review M4).
    ready: std::sync::atomic::AtomicBool,
    buckets: Mutex<HashMap<String, Bucket>>,
    all: Mutex<Bucket>,
    /// Requests with no trigger's token, by client address (`ip_key`: an IPv6 address by its /64).
    failures: Mutex<HashMap<String, Bucket>>,
    /// Bad signatures, by trigger: they never slow down another address's delivery.
    bad_signatures: Mutex<HashMap<String, Bucket>>,
    /// Deliveries handed to the node, by (trigger, body hash) and (trigger, delivery id).
    seen: Mutex<HashMap<(String, String), Instant>>,
    refused: Mutex<IntakeRefused>,
}

impl Default for Intake {
    fn default() -> Intake {
        Intake {
            table: Default::default(),
            ready: Default::default(),
            buckets: Default::default(),
            all: Mutex::new(Bucket::full(ALL_BURST, Instant::now())),
            failures: Default::default(),
            bad_signatures: Default::default(),
            seen: Default::default(),
            refused: Default::default(),
        }
    }
}

/// Takes a token from `key`'s failure bucket in `m` (bounded: the oldest forgotten first), and
/// whether one was left.
fn charge(m: &mut HashMap<String, Bucket>, key: &str, at: Instant) -> bool {
    if m.len() >= FAILURE_ADDRESSES && !m.contains_key(key) {
        if let Some(oldest) = m.iter().min_by_key(|(_, b)| b.at).map(|(k, _)| k.clone()) {
            m.remove(&oldest);
        }
    }
    m.entry(key.to_string()).or_insert_with(|| Bucket::full(FAILURES_BURST, at)).take(FAILURES_PER_MIN, FAILURES_BURST, at)
}

impl Intake {
    /// The node's table, and whether it has had the control host's.
    pub fn set_table(&self, t: Vec<IntakeTrigger>, ready: bool) {
        let served: Vec<String> = t.iter().map(|x| x.trigger.clone()).collect();
        self.buckets.lock().expect("buckets").retain(|k, _| served.contains(k));
        self.bad_signatures.lock().expect("bad").retain(|k, _| served.contains(k));
        *self.table.write().expect("table") = t;
        self.ready.store(ready, std::sync::atomic::Ordering::Relaxed);
    }

    /// The refusals counted since the last call.
    pub fn take_refused(&self) -> IntakeRefused {
        std::mem::take(&mut *self.refused.lock().expect("refused"))
    }

    /// Before any of the body is read: the path's shape and its trigger's token, from client
    /// address `ip`. A request with a trigger's token goes on whatever its address did before; only
    /// one without is charged to its address, and an address that keeps sending those is answered
    /// 429 instead of 404 (#714 review F3). The trigger, or the answer.
    pub fn admit(&self, path: &str, ip: IpAddr, at: Instant) -> std::result::Result<IntakeTrigger, Outcome> {
        if !self.ready.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Outcome::Answer(StatusCode::SERVICE_UNAVAILABLE, "try later"));
        }
        let mut parts = path.trim_start_matches('/').split('/');
        let found = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            // The token's shape first: a path can't make intake hash much.
            (Some("hook"), Some(trigger), Some(token), None) if ik::token_shape(token) => {
                let h = ik::token_sha256(token);
                self.table
                    .read()
                    .expect("table")
                    .iter()
                    .find(|t| t.trigger == trigger && ik::same(h.as_bytes(), t.token_sha256.as_bytes()))
                    .cloned()
            }
            _ => None,
        };
        match found {
            // Served, but its secret didn't read this time: try later, and nobody's failure.
            Some(t) if t.unavailable => Err(Outcome::Answer(StatusCode::SERVICE_UNAVAILABLE, "try later")),
            Some(t) => Ok(t),
            None => {
                let key = crate::serve::limits::ip_key(ip);
                let left = charge(&mut self.failures.lock().expect("failures"), &key, at);
                let mut r = self.refused.lock().expect("refused");
                if left {
                    r.token += 1;
                    Err(Outcome::Answer(StatusCode::NOT_FOUND, "not found"))
                } else {
                    r.rate += 1;
                    Err(Outcome::Answer(StatusCode::TOO_MANY_REQUESTS, "slow down"))
                }
            }
        }
    }

    /// Whether `t` has had this delivery (its body's hash, or its id) handed over recently.
    fn seen(&self, t: &str, raw: &str, delivery: &str, at: Instant) -> bool {
        let mut m = self.seen.lock().expect("seen");
        let fresh = |k: &(String, String), m: &HashMap<(String, String), Instant>| {
            m.get(k).is_some_and(|when| at.saturating_duration_since(*when) < Duration::from_secs(SEEN_SECS))
        };
        let (a, b) = ((t.to_string(), format!("b:{raw}")), (t.to_string(), format!("d:{delivery}")));
        let hit = fresh(&a, &m) || fresh(&b, &m);
        m.retain(|_, when| at.saturating_duration_since(*when) < Duration::from_secs(SEEN_SECS));
        hit
    }

    /// Remembers a delivery the node took.
    pub fn remember(&self, e: &IntakeEvent, at: Instant) {
        let mut m = self.seen.lock().expect("seen");
        while m.len() + 2 > SEEN_MAX {
            let Some(oldest) = m.iter().min_by_key(|(_, w)| **w).map(|(k, _)| k.clone()) else { break };
            m.remove(&oldest);
        }
        m.insert((e.trigger.clone(), format!("b:{}", e.raw_sha256)), at);
        m.insert((e.trigger.clone(), format!("d:{}", e.delivery)), at);
    }

    /// With the body: the signature, a delivery seen before, then (verified and new) the trigger's
    /// rate, then GitHub's event and repository. `header` gets a header by its lower-case name;
    /// `now` is Unix s.
    pub fn verify(&self, t: &IntakeTrigger, header: &dyn Fn(&str) -> Option<String>, body: &[u8], now: i64, at: Instant) -> Outcome {
        let github = t.kind == "github";
        let delivery_header = header(if github { ik::GITHUB_DELIVERY } else { ik::GENERIC_DELIVERY });
        let timestamp = header(ik::GENERIC_TIMESTAMP);
        let signed = if github {
            ik::signature_ok(t.secret.as_bytes(), body, header(ik::GITHUB_SIGNATURE).as_deref())
        } else {
            ik::generic_check(
                t.secret.as_bytes(),
                timestamp.as_deref(),
                delivery_header.as_deref(),
                body,
                header(ik::GENERIC_SIGNATURE).as_deref(),
                now,
            )
            .is_ok()
        };
        if !signed {
            // Charged to the trigger, never to an address another sender shares.
            let left = charge(&mut self.bad_signatures.lock().expect("bad"), &t.trigger, at);
            let mut r = self.refused.lock().expect("refused");
            r.signature += 1;
            return match left {
                true => Outcome::Answer(StatusCode::UNAUTHORIZED, "bad signature"),
                false => Outcome::Answer(StatusCode::TOO_MANY_REQUESTS, "slow down"),
            };
        }
        let Some(delivery) = ik::delivery_id(delivery_header.as_deref(), body) else {
            self.refused.lock().expect("refused").other += 1;
            return Outcome::Answer(StatusCode::BAD_REQUEST, "bad delivery id");
        };
        // What the event's dedup is keyed on: GitHub's body (its id and time aren't signed), or a
        // generic delivery's whole signed message (time, id and body), so the same body sent again
        // as a new delivery isn't taken for a resend (#714 review F12).
        let raw = if github {
            ik::body_sha256(body)
        } else {
            let ts = timestamp.as_deref().and_then(|t| t.trim().parse::<i64>().ok()).unwrap_or(0);
            ik::body_sha256(&ik::generic_signed(ts, delivery_header.as_deref().map(str::trim).unwrap_or(""), body))
        };
        // Sent again (a replay, or a resend): 202, nothing spooled, nothing charged (#714 review F2).
        if self.seen(&t.trigger, &raw, &delivery, at) {
            return Outcome::Answer(StatusCode::ACCEPTED, "already had it");
        }
        // Only a verified, new delivery counts against its trigger: a leaked URL or a replayed body
        // alone can't starve it.
        {
            let mut b = self.buckets.lock().expect("buckets");
            let mine = b.entry(t.trigger.clone()).or_insert_with(|| Bucket::full(PER_TRIGGER_BURST, at));
            if !mine.take(PER_TRIGGER_PER_MIN, PER_TRIGGER_BURST, at) || !self.all.lock().expect("all").take(ALL_PER_MIN, ALL_BURST, at) {
                drop(b);
                self.refused.lock().expect("refused").rate += 1;
                return Outcome::Answer(StatusCode::TOO_MANY_REQUESTS, "slow down");
            }
        }
        let (kind, fields) = if github {
            let event = header(ik::GITHUB_EVENT).unwrap_or_default();
            // What wicket will never fire on is answered 202, so GitHub doesn't send it again.
            if !t.events.contains(&event) {
                return Outcome::Answer(StatusCode::ACCEPTED, "not listened to");
            }
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
                self.refused.lock().expect("refused").other += 1;
                return Outcome::Answer(StatusCode::BAD_REQUEST, "not json");
            };
            // GitHub's repository names ignore case.
            let same_repo = match (ik::github_repo(&v), t.repo.as_deref()) {
                (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
                _ => false,
            };
            if !same_repo {
                self.refused.lock().expect("refused").other += 1;
                return Outcome::Answer(StatusCode::ACCEPTED, "another repository");
            }
            (event.clone(), ik::github_fields(&event, &v))
        } else {
            ("webhook".to_string(), ik::generic_fields(body))
        };
        Outcome::Spool(Box::new(IntakeEvent {
            id: String::new(),
            trigger: t.trigger.clone(),
            kind,
            delivery,
            received_at: now,
            fields,
            raw_sha256: raw,
            bytes: body.len() as u64,
        }))
    }
}

/// One request to `node serve`'s intake socket, and its answer.
async fn ask(sock: &std::path::Path, req: &serde_json::Value) -> Result<serde_json::Value> {
    let c = tokio::net::UnixStream::connect(sock).await.with_context(|| format!("{} (is wicket node serve running?)", sock.display()))?;
    let (rd, mut wr) = c.into_split();
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    wr.write_all(&line).await?;
    let mut answer = String::new();
    tokio::time::timeout(Duration::from_secs(10), tokio::io::BufReader::new(rd).read_line(&mut answer))
        .await
        .context("the node didn't answer")??;
    Ok(serde_json::from_str(&answer)?)
}

/// Who is in front of intake: reverse proxies whose `X-Forwarded-For` it believes (`--trusted-proxy`,
/// as the console's, #123). A request from one is its client's, and no per-address connection cap
/// applies to it.
pub type Trusted = Arc<Vec<crate::serve::limits::Cidr>>;

/// `wicket node intake`: listens on `listen` (with TLS from `tls`'s certificate and key files, or
/// plain HTTP behind a reverse proxy that has them, named in `trusted`), and talks to its node over
/// `sock`.
pub async fn serve(listen: std::net::SocketAddr, tls: Option<(PathBuf, PathBuf)>, sock: PathBuf, trusted: Trusted) -> Result<()> {
    let intake = Arc::new(Intake::default());
    // The table, and refusals reported, every TABLE_EVERY.
    {
        let (i, s) = (intake.clone(), sock.clone());
        tokio::spawn(async move {
            loop {
                match ask(&s, &serde_json::json!({ "op": "table" })).await {
                    Ok(v) => match serde_json::from_value::<Vec<IntakeTrigger>>(v["triggers"].clone()) {
                        Ok(t) => i.set_table(t, v["ready"].as_bool().unwrap_or(false)),
                        Err(e) => eprintln!("wicket intake: the node's table doesn't read: {e}"),
                    },
                    Err(e) => {
                        // Not served while the node can't be asked: every delivery is a 503 meanwhile.
                        i.set_table(vec![], false);
                        eprintln!("wicket intake: {e:#}");
                    }
                }
                let r = i.take_refused();
                if r.total() > 0 {
                    let _ = ask(&s, &serde_json::json!({ "op": "refused", "counts": r })).await;
                }
                tokio::time::sleep(TABLE_EVERY).await;
            }
        });
    }
    let acceptor = match tls {
        Some((cert, key)) => {
            let ck = crate::serve::tls::certified_key_from_pem(&std::fs::read(&cert)?, &std::fs::read(&key)?)
                .with_context(|| format!("{} and {}", cert.display(), key.display()))?;
            let mut cfg = rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(Arc::new(Single(Arc::new(ck))));
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            Some(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
        }
        None => None,
    };
    let listener = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("listening on {listen}"))?;
    eprintln!("wicket intake: listening on {listen}{}", if acceptor.is_some() { " (TLS)" } else { " (plain HTTP: put TLS in front)" });
    accept(listener, acceptor, intake, sock, limits(), trusted).await
}

/// Accepts connections as the console does: over the cap (overall, or from one address) they are
/// closed at once; TLS is negotiated within the handshake timeout.
async fn accept(
    listener: tokio::net::TcpListener,
    acceptor: Option<tokio_rustls::TlsAcceptor>,
    intake: Arc<Intake>,
    sock: PathBuf,
    limits: crate::serve::net::Limits,
    trusted: Trusted,
) -> Result<()> {
    let slots = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    let per_ip = Arc::new(crate::serve::net::PerIp::default());
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else { continue };
        let guard = if trusted.iter().any(|c| c.contains(peer.ip())) {
            None
        } else {
            match per_ip.enter(peer.ip(), limits.per_ip_connections) {
                Some(g) => Some(g),
                None => continue,
            }
        };
        let _ = tcp.set_nodelay(true);
        let (i, s, acc, lim, tr) = (intake.clone(), sock.clone(), acceptor.clone(), limits.clone(), trusted.clone());
        tokio::spawn(async move {
            let _held = (permit, guard);
            match acc {
                Some(a) => {
                    if let Ok(Ok(io)) = tokio::time::timeout(lim.handshake_timeout, a.accept(tcp)).await {
                        serve_conn(io, peer.ip(), i, s, lim, tr).await;
                    }
                }
                None => serve_conn(tcp, peer.ip(), i, s, lim, tr).await,
            }
        });
    }
}

async fn serve_conn<I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
    io: I,
    ip: IpAddr,
    i: Arc<Intake>,
    sock: PathBuf,
    lim: crate::serve::net::Limits,
    trusted: Trusted,
) {
    let body_timeout = lim.body_timeout;
    let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        // The client's address: the peer's, or behind a trusted proxy, the one it forwards.
        let lines: Vec<Option<&str>> = req.headers().get_all("x-forwarded-for").iter().map(|v| v.to_str().ok()).collect();
        let client = crate::serve::limits::client_ip(ip, &lines, &trusted);
        handle(i.clone(), sock.clone(), client, body_timeout, req)
    });
    let mut b = hyper::server::conn::http1::Builder::new();
    b.timer(TokioTimer::new())
        .header_read_timeout(lim.header_timeout)
        .max_headers(lim.max_headers)
        .max_buf_size(lim.max_header_bytes.max(8192))
        .half_close(false)
        .keep_alive(true);
    let conn = b.serve_connection(TokioIo::new(io), svc);
    tokio::pin!(conn);
    tokio::select! {
        _ = conn.as_mut() => {}
        _ = tokio::time::sleep(lim.conn_lifetime) => {
            conn.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(lim.body_timeout, conn).await;
        }
    }
}

#[derive(Debug)]
struct Single(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for Single {
    fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn answer(code: StatusCode, word: &'static str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(format!("{word}\n"))));
    *r.status_mut() = code;
    if code != StatusCode::ACCEPTED {
        // Nothing more is read from a refused request's connection.
        r.headers_mut().insert(hyper::header::CONNECTION, hyper::header::HeaderValue::from_static("close"));
    }
    r
}

async fn handle(
    i: Arc<Intake>,
    sock: PathBuf,
    ip: IpAddr,
    body_timeout: Duration,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    if req.method() != hyper::Method::POST {
        return Ok(answer(StatusCode::METHOD_NOT_ALLOWED, "POST only"));
    }
    let at = Instant::now();
    // The path and the token before any of the body is read.
    let t = match i.admit(req.uri().path(), ip, at) {
        Ok(t) => t,
        Err(Outcome::Answer(code, word)) => return Ok(answer(code, word)),
        Err(Outcome::Spool(_)) => unreachable!("admit spools nothing"),
    };
    let too_big = req
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|n| n > ik::MAX_BODY);
    if too_big {
        i.refused.lock().expect("refused").other += 1;
        return Ok(answer(StatusCode::PAYLOAD_TOO_LARGE, "too large"));
    }
    let headers = req.headers().clone();
    let body = match tokio::time::timeout(body_timeout, Limited::new(req.into_body(), ik::MAX_BODY).collect()).await {
        Ok(Ok(b)) => b.to_bytes(),
        Ok(Err(_)) => {
            i.refused.lock().expect("refused").other += 1;
            return Ok(answer(StatusCode::PAYLOAD_TOO_LARGE, "too large"));
        }
        Err(_) => {
            i.refused.lock().expect("refused").other += 1;
            return Ok(answer(StatusCode::REQUEST_TIMEOUT, "too slow"));
        }
    };
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(String::from);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    Ok(match i.verify(&t, &header, &body, now, at) {
        Outcome::Answer(code, word) => answer(code, word),
        Outcome::Spool(e) => match ask(&sock, &serde_json::json!({ "op": "deliver", "event": e })).await {
            Ok(v) if v["ok"] == true => {
                // Only once the node has it: one it refused may be sent again, and taken then.
                i.remember(&e, at);
                answer(StatusCode::ACCEPTED, "accepted")
            }
            // Full, or the node not up: the sender tries again later.
            _ => answer(StatusCode::SERVICE_UNAVAILABLE, "try later"),
        },
    })
}

/// Checks `wicket node intake`'s arguments: a certificate needs its key.
pub fn tls_pair(cert: Option<PathBuf>, key: Option<PathBuf>) -> Result<Option<(PathBuf, PathBuf)>> {
    match (cert, key) {
        (Some(c), Some(k)) => Ok(Some((c, k))),
        (None, None) => Ok(None),
        _ => bail!("--tls-cert and --tls-key go together"),
    }
}

#[cfg(test)]
mod tests;
