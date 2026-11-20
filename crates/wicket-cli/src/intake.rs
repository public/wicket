//! `wicket intake serve` (#578 step 4; docs/explanation/trigger-intake.md): webhook intake, a small
//! service of its own on a node, beside its `wicket node serve`.
//!
//! It holds no ledger, no vault, no authority and no files. It knows the triggers it serves (their
//! token's sha256, verify secret, and for GitHub the repository and events) from its `node serve`,
//! over `<node dir>/ctl/intake.sock`, every [`TABLE_EVERY`]. A delivery is checked (path, size,
//! token, rate, signature, GitHub's event and repository), normalised into a capped set of fields
//! (`wicket_core::intake`), and handed to `node serve`, which spools it until the control host
//! takes it. The answer is a status and a fixed word: never anything of the payload.

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use wicket_core::intake::{self as ik, IntakeEvent, IntakeRefused, IntakeTrigger};

/// How often the table is fetched again (and refusals reported).
pub const TABLE_EVERY: Duration = Duration::from_secs(10);
/// A trigger's deliveries: a token bucket of this many a minute …
pub const PER_TRIGGER_PER_MIN: f64 = 60.0;
/// … with this burst.
pub const PER_TRIGGER_BURST: f64 = 20.0;
/// Every trigger's together.
pub const ALL_PER_MIN: f64 = 600.0;
pub const ALL_BURST: f64 = 100.0;
/// How long a request may take to send its body.
const BODY_TIMEOUT: Duration = Duration::from_secs(30);

struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn full(burst: f64, at: Instant) -> Bucket {
        Bucket { tokens: burst, at }
    }

    fn take(&mut self, per_min: f64, burst: f64, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        self.tokens = (self.tokens + dt * per_min / 60.0).min(burst);
        self.at = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
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

/// Intake's state: the table, the rate buckets, and the refusals not yet reported.
pub struct Intake {
    table: RwLock<Vec<IntakeTrigger>>,
    buckets: Mutex<HashMap<String, Bucket>>,
    all: Mutex<Bucket>,
    refused: Mutex<IntakeRefused>,
}

impl Default for Intake {
    fn default() -> Intake {
        Intake {
            table: Default::default(),
            buckets: Default::default(),
            all: Mutex::new(Bucket::full(ALL_BURST, Instant::now())),
            refused: Default::default(),
        }
    }
}

impl Intake {
    pub fn set_table(&self, t: Vec<IntakeTrigger>) {
        let served: Vec<String> = t.iter().map(|x| x.trigger.clone()).collect();
        self.buckets.lock().expect("buckets").retain(|k, _| served.contains(k));
        *self.table.write().expect("table") = t;
    }

    fn refuse(&self, f: impl FnOnce(&mut IntakeRefused), code: StatusCode, word: &'static str) -> Outcome {
        f(&mut self.refused.lock().expect("refused"));
        Outcome::Answer(code, word)
    }

    /// The refusals counted since the last call.
    pub fn take_refused(&self) -> IntakeRefused {
        std::mem::take(&mut *self.refused.lock().expect("refused"))
    }

    /// Decides one delivery: `path`, a header getter (lower-case names), the body (already capped
    /// at [`ik::MAX_BODY`]), at `now` (Unix s) and `at` (for the rate buckets).
    pub fn decide(&self, path: &str, header: &dyn Fn(&str) -> Option<String>, body: &[u8], now: i64, at: Instant) -> Outcome {
        let mut parts = path.trim_start_matches('/').split('/');
        let (Some("hook"), Some(trigger), Some(token), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
            return self.refuse(|r| r.token += 1, StatusCode::NOT_FOUND, "not found");
        };
        // The token's shape first: a path can't make intake hash much.
        let t = if ik::token_shape(token) {
            let h = ik::token_sha256(token);
            self.table
                .read()
                .expect("table")
                .iter()
                .find(|t| t.trigger == trigger && ik::same(h.as_bytes(), t.token_sha256.as_bytes()))
                .cloned()
        } else {
            None
        };
        let Some(t) = t else { return self.refuse(|r| r.token += 1, StatusCode::NOT_FOUND, "not found") };
        {
            let mut b = self.buckets.lock().expect("buckets");
            let mine = b.entry(t.trigger.clone()).or_insert_with(|| Bucket::full(PER_TRIGGER_BURST, at));
            if !mine.take(PER_TRIGGER_PER_MIN, PER_TRIGGER_BURST, at) || !self.all.lock().expect("all").take(ALL_PER_MIN, ALL_BURST, at) {
                drop(b);
                return self.refuse(|r| r.rate += 1, StatusCode::TOO_MANY_REQUESTS, "slow down");
            }
        }
        let github = t.kind == "github";
        let sig = header(if github { ik::GITHUB_SIGNATURE } else { ik::GENERIC_SIGNATURE });
        if !ik::signature_ok(t.secret.as_bytes(), body, sig.as_deref()) {
            return self.refuse(|r| r.signature += 1, StatusCode::UNAUTHORIZED, "bad signature");
        }
        let Some(delivery) = ik::delivery_id(header(if github { ik::GITHUB_DELIVERY } else { ik::GENERIC_DELIVERY }).as_deref(), body)
        else {
            return self.refuse(|r| r.other += 1, StatusCode::BAD_REQUEST, "bad delivery id");
        };
        let (kind, fields) = if github {
            let event = header(ik::GITHUB_EVENT).unwrap_or_default();
            // What wicket will never fire on is answered 202, so GitHub doesn't send it again.
            if !t.events.contains(&event) {
                return Outcome::Answer(StatusCode::ACCEPTED, "not listened to");
            }
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
                return self.refuse(|r| r.other += 1, StatusCode::BAD_REQUEST, "not json");
            };
            if ik::github_repo(&v).as_deref() != t.repo.as_deref() {
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
            raw_sha256: ik::body_sha256(body),
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

/// `wicket intake serve`: listens on `listen` (with TLS from `tls`'s certificate and key files,
/// or plain HTTP behind a reverse proxy that has them), for the node at `node_dir`.
pub async fn serve(listen: std::net::SocketAddr, tls: Option<(PathBuf, PathBuf)>, node_dir: PathBuf) -> Result<()> {
    let sock = node_dir.join("ctl").join("intake.sock");
    let intake = Arc::new(Intake::default());
    // The table, and refusals reported, every TABLE_EVERY.
    {
        let (i, s) = (intake.clone(), sock.clone());
        tokio::spawn(async move {
            loop {
                match ask(&s, &serde_json::json!({ "op": "table" })).await {
                    Ok(v) => match serde_json::from_value::<Vec<IntakeTrigger>>(v["triggers"].clone()) {
                        Ok(t) => i.set_table(t),
                        Err(e) => eprintln!("wicket intake: the node's table doesn't read: {e}"),
                    },
                    Err(e) => {
                        // Not served while the node can't be asked: every delivery is a 404 meanwhile.
                        i.set_table(vec![]);
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
    loop {
        let Ok((tcp, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        };
        let (i, s, acc) = (intake.clone(), sock.clone(), acceptor.clone());
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |req| handle(i.clone(), s.clone(), req));
            let b = hyper::server::conn::http1::Builder::new();
            match acc {
                Some(a) => {
                    if let Ok(Ok(io)) = tokio::time::timeout(Duration::from_secs(10), a.accept(tcp)).await {
                        let _ = b.serve_connection(hyper_util::rt::TokioIo::new(io), svc).await;
                    }
                }
                None => {
                    let _ = b.serve_connection(hyper_util::rt::TokioIo::new(tcp), svc).await;
                }
            }
        });
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
    r
}

async fn handle(
    i: Arc<Intake>,
    sock: PathBuf,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, std::convert::Infallible> {
    if req.method() != hyper::Method::POST {
        return Ok(answer(StatusCode::METHOD_NOT_ALLOWED, "POST only"));
    }
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();
    let body = match tokio::time::timeout(BODY_TIMEOUT, Limited::new(req.into_body(), ik::MAX_BODY).collect()).await {
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
    Ok(match i.decide(&path, &header, &body, now, Instant::now()) {
        Outcome::Answer(code, word) => answer(code, word),
        Outcome::Spool(e) => match ask(&sock, &serde_json::json!({ "op": "deliver", "event": e })).await {
            Ok(v) if v["ok"] == true => answer(StatusCode::ACCEPTED, "accepted"),
            // Full, or the node not up: the sender tries again later.
            _ => answer(StatusCode::SERVICE_UNAVAILABLE, "try later"),
        },
    })
}

/// Checks `wicket intake serve`'s arguments: a certificate needs its key.
pub fn tls_pair(cert: Option<PathBuf>, key: Option<PathBuf>) -> Result<Option<(PathBuf, PathBuf)>> {
    match (cert, key) {
        (Some(c), Some(k)) => Ok(Some((c, k))),
        (None, None) => Ok(None),
        _ => bail!("--tls-cert and --tls-key go together"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trig(kind: &str, token: &str) -> IntakeTrigger {
        IntakeTrigger {
            trigger: "trg_1".into(),
            kind: kind.into(),
            token_sha256: ik::token_sha256(token),
            secret: "s3cret".into(),
            repo: (kind == "github").then(|| "acme/app".to_string()),
            events: if kind == "github" { vec!["check_suite".into()] } else { vec![] },
        }
    }

    fn sign(body: &[u8]) -> String {
        format!("sha256={}", hex::encode(ik::hmac_sha256(b"s3cret", body)))
    }

    fn headers(h: &[(&str, String)]) -> impl Fn(&str) -> Option<String> {
        let h: Vec<(String, String)> = h.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
        move |n: &str| h.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone())
    }

    /// A generic delivery: only the right path, token and signature are spooled, and each refusal
    /// is counted by why.
    #[test]
    fn a_generic_delivery_is_checked_in_order() {
        let token = ik::new_token().unwrap();
        let i = Intake::default();
        i.set_table(vec![trig("webhook", &token)]);
        let body = br#"{"status":"failed","n":3}"#;
        let at = Instant::now();
        let good = headers(&[(ik::GENERIC_SIGNATURE, sign(body)), (ik::GENERIC_DELIVERY, "d-1".into())]);
        let path = format!("/hook/trg_1/{token}");
        let Outcome::Spool(e) = i.decide(&path, &good, body, 1000, at) else { panic!("refused") };
        assert_eq!((e.trigger.as_str(), e.delivery.as_str(), e.kind.as_str()), ("trg_1", "d-1", "webhook"));
        assert_eq!(e.fields, serde_json::json!({ "status": "failed", "n": 3 }));
        let other = ik::new_token().unwrap();
        assert_eq!(i.decide(&format!("/hook/trg_1/{other}"), &good, body, 1000, at), Outcome::Answer(StatusCode::NOT_FOUND, "not found"));
        assert_eq!(i.decide(&format!("/hook/trg_2/{token}"), &good, body, 1000, at), Outcome::Answer(StatusCode::NOT_FOUND, "not found"));
        assert_eq!(i.decide("/hook/trg_1", &good, body, 1000, at), Outcome::Answer(StatusCode::NOT_FOUND, "not found"));
        let forged = headers(&[(ik::GENERIC_SIGNATURE, sign(b"other"))]);
        assert_eq!(i.decide(&path, &forged, body, 1000, at), Outcome::Answer(StatusCode::UNAUTHORIZED, "bad signature"));
        let r = i.take_refused();
        assert_eq!((r.token, r.signature), (3, 1));
        assert_eq!(i.take_refused().total(), 0, "reported once");
    }

    /// GitHub: its own signature header; events and repositories it doesn't listen to are 202 and
    /// dropped; the fields are the normalised ones.
    #[test]
    fn a_github_delivery_keeps_its_fields() {
        let token = ik::new_token().unwrap();
        let i = Intake::default();
        i.set_table(vec![trig("github", &token)]);
        let path = format!("/hook/trg_1/{token}");
        let body = serde_json::to_vec(&serde_json::json!({
            "action": "completed",
            "check_suite": { "conclusion": "failure", "head_branch": "fix", "pull_requests": [{ "number": 9 }] },
            "repository": { "full_name": "acme/app" }
        }))
        .unwrap();
        let h = |event: &str, body: &[u8]| {
            headers(&[(ik::GITHUB_SIGNATURE, sign(body)), (ik::GITHUB_EVENT, event.into()), (ik::GITHUB_DELIVERY, "g-1".into())])
        };
        let at = Instant::now();
        let Outcome::Spool(e) = i.decide(&path, &h("check_suite", &body), &body, 5, at) else { panic!("refused") };
        assert_eq!((e.kind.as_str(), e.fields["pr"]["number"].as_i64()), ("check_suite", Some(9)));
        assert_eq!(i.decide(&path, &h("push", &body), &body, 5, at), Outcome::Answer(StatusCode::ACCEPTED, "not listened to"));
        let elsewhere = serde_json::to_vec(&serde_json::json!({ "repository": { "full_name": "evil/app" } })).unwrap();
        assert_eq!(
            i.decide(&path, &h("check_suite", &elsewhere), &elsewhere, 5, at),
            Outcome::Answer(StatusCode::ACCEPTED, "another repository")
        );
        // The generic header doesn't sign a GitHub delivery.
        let generic = headers(&[(ik::GENERIC_SIGNATURE, sign(&body)), (ik::GITHUB_EVENT, "check_suite".into())]);
        assert_eq!(i.decide(&path, &generic, &body, 5, at), Outcome::Answer(StatusCode::UNAUTHORIZED, "bad signature"));
    }

    /// The service end to end, over TCP and its node's socket (a stand-in for `node serve`): a
    /// signed delivery is handed to the node and answered 202; a forged one is answered 401 and never
    /// reaches the node; a GET is refused. The table comes from the node.
    #[tokio::test]
    async fn the_service_hands_verified_deliveries_to_its_node() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = std::env::temp_dir().join(format!("wicket-intake-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("ctl")).unwrap();
        let token = ik::new_token().unwrap();
        let table = serde_json::json!({ "triggers": [trig("webhook", &token)] });
        let delivered = Arc::new(Mutex::new(vec![]));
        let sock = tokio::net::UnixListener::bind(dir.join("ctl").join("intake.sock")).unwrap();
        {
            let delivered = delivered.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((c, _)) = sock.accept().await else { return };
                    let (rd, mut wr) = c.into_split();
                    let mut line = String::new();
                    let _ = tokio::io::BufReader::new(rd).read_line(&mut line).await;
                    let req: serde_json::Value = serde_json::from_str(&line).unwrap_or_default();
                    let answer = match req["op"].as_str() {
                        Some("table") => table.clone(),
                        Some("deliver") => {
                            delivered.lock().unwrap().push(req["event"].clone());
                            serde_json::json!({ "ok": true })
                        }
                        _ => serde_json::json!({ "ok": true }),
                    };
                    let mut out = serde_json::to_vec(&answer).unwrap();
                    out.push(b'\n');
                    let _ = wr.write_all(&out).await;
                }
            });
        }
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        tokio::spawn(serve(addr, None, dir.clone()));
        let post = |path: String, headers: Vec<(&'static str, String)>, body: &'static [u8], method: &'static str| async move {
            let mut c = loop {
                if let Ok(c) = tokio::net::TcpStream::connect(addr).await {
                    break c;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            };
            let mut req = format!("{method} {path} HTTP/1.1\r\nhost: x\r\ncontent-length: {}\r\nconnection: close\r\n", body.len());
            for (k, v) in headers {
                req.push_str(&format!("{k}: {v}\r\n"));
            }
            req.push_str("\r\n");
            c.write_all(req.as_bytes()).await.unwrap();
            c.write_all(body).await.unwrap();
            let mut out = String::new();
            let _ = c.read_to_string(&mut out).await;
            out
        };
        let body: &'static [u8] = br#"{"status":"failed"}"#;
        let path = format!("/hook/trg_1/{token}");
        // The table arrives within a moment of starting.
        let mut answer = String::new();
        for _ in 0..50 {
            answer =
                post(path.clone(), vec![(ik::GENERIC_SIGNATURE, sign(body)), (ik::GENERIC_DELIVERY, "d-1".into())], body, "POST").await;
            if answer.starts_with("HTTP/1.1 202") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(answer.starts_with("HTTP/1.1 202"), "{answer}");
        assert!(!answer.contains("failed"), "the payload isn't echoed: {answer}");
        let forged = post(path.clone(), vec![(ik::GENERIC_SIGNATURE, sign(b"other"))], body, "POST").await;
        assert!(forged.starts_with("HTTP/1.1 401"), "{forged}");
        let get = post(path.clone(), vec![], b"", "GET").await;
        assert!(get.starts_with("HTTP/1.1 405"), "{get}");
        let d = delivered.lock().unwrap().clone();
        assert_eq!(d.len(), 1, "only the verified one reached the node");
        assert_eq!(
            (d[0]["trigger"].as_str(), d[0]["delivery"].as_str(), d[0]["fields"]["status"].as_str()),
            (Some("trg_1"), Some("d-1"), Some("failed"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Past its burst a trigger is slowed down, and the bucket fills again with time.
    #[test]
    fn a_trigger_is_rate_limited() {
        let token = ik::new_token().unwrap();
        let i = Intake::default();
        i.set_table(vec![trig("webhook", &token)]);
        let path = format!("/hook/trg_1/{token}");
        let body = b"{}";
        let h = headers(&[(ik::GENERIC_SIGNATURE, sign(body))]);
        let at = Instant::now();
        let mut ok = 0;
        for _ in 0..30 {
            if matches!(i.decide(&path, &h, body, 1, at), Outcome::Spool(_)) {
                ok += 1;
            }
        }
        assert_eq!(ok, PER_TRIGGER_BURST as usize);
        assert_eq!(i.take_refused().rate, 10);
        assert!(matches!(i.decide(&path, &h, body, 1, at + Duration::from_secs(2)), Outcome::Spool(_)), "a token a second comes back");
        // A trigger no longer served loses its bucket, and its deliveries are not found.
        i.set_table(vec![]);
        assert_eq!(i.decide(&path, &h, body, 1, at), Outcome::Answer(StatusCode::NOT_FOUND, "not found"));
    }
}
