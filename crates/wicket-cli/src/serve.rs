//! `wicket serve`: the operator console (design §14.1.3, proof-of-concept cut), signed in and
//! driven with passkeys.
//!
//! Security flow:
//! 1. **Bootstrap.** At start-up, *only if no operator passkey exists yet*, a one-time enrolment link
//!    is printed. It is single-use, expires after 10 minutes, and the session it creates can do one
//!    thing: register a passkey. It cannot view runs or decide anything.
//! 2. **Sign-in** is a passkey assertion (user verification required) giving a 12-hour session.
//!    Adding further passkeys needs a signed-in operator.
//! 3. **Every approve or deny is a fresh passkey assertion** whose challenge is
//!    `sha256(nonce || canonical decision JSON)`: the request id, method, host, path, decision, uses
//!    and lifetime. The server re-reads the request, verifies the signature, consumes the challenge
//!    (single use, 2-minute expiry), applies the decision, and writes the signed triple
//!    (clientDataJSON, authenticatorData, signature) into the audit log for offline re-verification.
//!
//! The console binds to loopback; WebAuthn needs a secure context, so open it as
//! http://localhost:PORT (or behind HTTPS on a tailnet with --origin/--rp-id). `wicket approve` on the
//! host remains a break-glass path and is audited as such.

use crate::ledger_path;
use anyhow::{bail, Result};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use wicket_auth::{b64u, decision_challenge, unb64u, Credential, RelyingParty};
use wicket_core::TenantId;
use wicket_store::{Approval, Ledger, OperatorCredential};

const PAGE: &str = include_str!("console.html");
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const CHALLENGE_TTL: Duration = Duration::from_secs(120);

#[derive(Clone, PartialEq)]
enum SessionKind {
    Bootstrap,
    Operator { cred: String },
}

struct Session {
    kind: SessionKind,
    expires: Instant,
}

enum Purpose {
    Register,
    Login,
    Decision { decision_json: String, nonce: Vec<u8>, request: String, approve: bool, uses: Option<u32>, ttl_secs: u64 },
}

struct Pending {
    purpose: Purpose,
    session: Option<String>,
    expires: Instant,
}

struct State {
    rp: RelyingParty,
    tenant: TenantId,
    bootstrap: Mutex<Option<(String, Instant)>>,
    sessions: Mutex<HashMap<String, Session>>,
    challenges: Mutex<HashMap<String, Pending>>,
}

pub async fn serve(listen: &str, allow_remote: bool, origin: Option<String>, rp_id: Option<String>) -> Result<()> {
    let addr: std::net::SocketAddr = listen.parse()?;
    if !addr.ip().is_loopback() && !allow_remote {
        bail!("refusing to listen on {addr}: the PoC console is loopback-only (use an ssh tunnel or tailnet, or pass --allow-remote)");
    }
    let origin = origin.unwrap_or_else(|| format!("http://localhost:{}", addr.port()));
    let rp_id = rp_id.unwrap_or_else(|| "localhost".into());
    let tenant = TenantId::single();
    let has_passkeys = !Ledger::open(&ledger_path())?.operator_credentials(&tenant)?.is_empty();
    let state = Arc::new(State {
        rp: RelyingParty { rp_id, origin: origin.clone() },
        tenant,
        bootstrap: Mutex::new(None),
        sessions: Mutex::new(HashMap::new()),
        challenges: Mutex::new(HashMap::new()),
    });
    let listener = TcpListener::bind(addr).await?;
    println!("wicket console on {origin}/  (listening on {addr})");
    if has_passkeys {
        println!("sign in with your passkey. (Lost them all? On the host: wicket operator reset)");
    } else {
        let token = random_hex(24);
        *state.bootstrap.lock().expect("lock") = Some((token.clone(), Instant::now() + Duration::from_secs(600)));
        println!("no operator passkey yet. Enrol one within 10 minutes (single use):");
        println!("  {origin}/enrol?t={token}");
    }
    loop {
        let (stream, _) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, hyper::Error>(route(req, &state).await) }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
        });
    }
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
    b
}

fn random_hex(n: usize) -> String {
    random_bytes(n).iter().map(|x| format!("{x:02x}")).collect()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn resp(status: StatusCode, ctype: &str, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", ctype)
        .header("cache-control", "no-store")
        .header("x-frame-options", "DENY")
        .header("referrer-policy", "no-referrer")
        .header("content-security-policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
        .body(Full::new(body.into()))
        .expect("response")
}

fn json_resp(status: StatusCode, v: Value) -> Response<Full<Bytes>> {
    resp(status, "application/json", v.to_string())
}

fn err(status: StatusCode, msg: impl std::fmt::Display) -> Response<Full<Bytes>> {
    json_resp(status, json!({ "error": msg.to_string() }))
}

fn cookie_sid(req: &Request<Incoming>) -> Option<String> {
    req.headers()
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix("wicket_sid=").map(String::from))
}

fn set_session(state: &State, kind: SessionKind) -> String {
    let sid = random_hex(32);
    let mut s = state.sessions.lock().expect("lock");
    let now = Instant::now();
    s.retain(|_, v| v.expires > now);
    s.insert(sid.clone(), Session { kind, expires: now + SESSION_TTL });
    format!("wicket_sid={sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}", SESSION_TTL.as_secs())
}

fn session(state: &State, sid: &Option<String>) -> Option<(String, SessionKind)> {
    let sid = sid.as_ref()?;
    let s = state.sessions.lock().expect("lock");
    s.get(sid).filter(|v| v.expires > Instant::now()).map(|v| (sid.clone(), v.kind.clone()))
}

fn new_challenge(state: &State, challenge: Vec<u8>, purpose: Purpose, session: Option<String>) -> String {
    let key = b64u(&challenge);
    let mut c = state.challenges.lock().expect("lock");
    let now = Instant::now();
    c.retain(|_, v| v.expires > now);
    c.insert(key.clone(), Pending { purpose, session, expires: now + CHALLENGE_TTL });
    key
}

/// Removes and returns a pending challenge (single use).
fn take_challenge(state: &State, key: &str) -> Option<Pending> {
    let p = state.challenges.lock().expect("lock").remove(key)?;
    (p.expires > Instant::now()).then_some(p)
}

fn creds(state: &State) -> Result<Vec<OperatorCredential>> {
    Ok(Ledger::open(&ledger_path())?.operator_credentials(&state.tenant)?)
}

async fn json_body(req: Request<Incoming>) -> Option<Value> {
    let b = Limited::new(req.into_body(), 64 * 1024).collect().await.ok()?.to_bytes();
    serde_json::from_slice(&b).ok()
}

fn field_b64(v: &Value, k: &str) -> Option<Vec<u8>> {
    v.get(k).and_then(|s| s.as_str()).and_then(|s| unb64u(s).ok())
}

async fn route(req: Request<Incoming>, state: &State) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let sid = cookie_sid(&req);

    if method == Method::GET {
        return match path.as_str() {
            "/" => resp(StatusCode::OK, "text/html; charset=utf-8", PAGE),
            "/enrol" => {
                let t = req.uri().query().unwrap_or("").split('&').find_map(|kv| kv.strip_prefix("t=")).unwrap_or("");
                let mut b = state.bootstrap.lock().expect("lock");
                let ok = matches!(&*b, Some((tok, exp)) if *exp > Instant::now() && ct_eq(tok.as_bytes(), t.as_bytes()));
                if !ok {
                    return resp(StatusCode::FORBIDDEN, "text/plain", "this enrolment link is invalid, used or expired");
                }
                *b = None; // single use
                drop(b);
                let cookie = set_session(state, SessionKind::Bootstrap);
                Response::builder().status(StatusCode::SEE_OTHER).header("location", "/").header("set-cookie", cookie).body(Full::new(Bytes::new())).expect("response")
            }
            "/api/me" => {
                let n = creds(state).map(|c| c.len()).unwrap_or(0);
                let who = match session(state, &sid) {
                    Some((_, SessionKind::Operator { cred })) => json!({ "state": "operator", "credential": cred }),
                    Some((_, SessionKind::Bootstrap)) => json!({ "state": "bootstrap" }),
                    None => json!({ "state": "none" }),
                };
                json_resp(StatusCode::OK, json!({ "who": who, "passkeys": n, "rp_id": state.rp.rp_id }))
            }
            "/api/state" => match session(state, &sid) {
                Some((_, SessionKind::Operator { .. })) => match dashboard(state) {
                    Ok(v) => json_resp(StatusCode::OK, v),
                    Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
                },
                _ => err(StatusCode::UNAUTHORIZED, "sign in with your passkey"),
            },
            _ => resp(StatusCode::NOT_FOUND, "text/plain", "not found"),
        };
    }
    if method != Method::POST {
        return resp(StatusCode::METHOD_NOT_ALLOWED, "text/plain", "method not allowed");
    }
    // Every POST: the custom header (no cross-site form or simple request can send it).
    if req.headers().get("x-wicket-csrf").map(|v| v.as_bytes()) != Some(b"1") {
        return err(StatusCode::FORBIDDEN, "missing x-wicket-csrf header");
    }
    let sess = session(state, &sid);
    let Some(body) = json_body(req).await else {
        return err(StatusCode::BAD_REQUEST, "bad JSON body");
    };
    match path.as_str() {
        "/api/register/begin" => {
            // Bootstrap sessions may enrol only while no passkey exists; afterwards a signed-in operator must.
            let n = creds(state).map(|c| c.len()).unwrap_or(0);
            let allowed = matches!(&sess, Some((_, SessionKind::Operator { .. }))) || (matches!(&sess, Some((_, SessionKind::Bootstrap))) && n == 0);
            if !allowed {
                return err(StatusCode::FORBIDDEN, "enrolling a passkey needs the enrolment link (first passkey) or a signed-in operator");
            }
            let challenge = random_bytes(32);
            let key = new_challenge(state, challenge.clone(), Purpose::Register, sess.map(|s| s.0));
            let exclude: Vec<Value> = creds(state).unwrap_or_default().iter().map(|c| json!({ "type": "public-key", "id": c.id })).collect();
            json_resp(StatusCode::OK, json!({ "publicKey": {
                "challenge": key,
                "rp": { "id": state.rp.rp_id, "name": "wicket" },
                "user": { "id": b64u(format!("operator-{}", state.tenant).as_bytes()), "name": "operator", "displayName": "wicket operator" },
                "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
                "authenticatorSelection": { "residentKey": "required", "userVerification": "required" },
                "attestation": "none", "timeout": 120000, "excludeCredentials": exclude
            }}))
        }
        "/api/register/finish" => {
            let (Some(ch), Some(cdj), Some(att)) = (body.get("challenge").and_then(|c| c.as_str()), field_b64(&body, "clientDataJSON"), field_b64(&body, "attestationObject")) else {
                return err(StatusCode::BAD_REQUEST, "challenge, clientDataJSON and attestationObject are required");
            };
            let Some(p) = take_challenge(state, ch) else { return err(StatusCode::FORBIDDEN, "unknown or expired challenge") };
            if !matches!(p.purpose, Purpose::Register) || p.session != sess.as_ref().map(|s| s.0.clone()) {
                return err(StatusCode::FORBIDDEN, "challenge was issued for something else");
            }
            match state.rp.verify_registration(&unb64u(ch).unwrap_or_default(), &cdj, &att) {
                Ok(c) => {
                    let name = body.get("name").and_then(|n| n.as_str()).unwrap_or("passkey").chars().take(40).collect::<String>();
                    let oc = OperatorCredential { id: b64u(&c.id), name, x: c.x, y: c.y, sign_count: c.sign_count };
                    let l = match Ledger::open(&ledger_path()) { Ok(l) => l, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
                    if let Err(e) = l.add_operator_credential(&state.tenant, &oc) {
                        return err(StatusCode::CONFLICT, e);
                    }
                    let _ = l.audit(&state.tenant, None, "operator.passkey_added", &json!({ "credential": oc.id, "name": oc.name, "via": if matches!(sess, Some((_, SessionKind::Bootstrap))) { "enrolment link" } else { "signed-in operator" } }));
                    // The enrolment session has done its one job: end it, so the next step is a real sign-in.
                    if let Some((sid, SessionKind::Bootstrap)) = &sess {
                        state.sessions.lock().expect("lock").remove(sid);
                    }
                    json_resp(StatusCode::OK, json!({ "ok": "passkey registered; now sign in with it" }))
                }
                Err(e) => err(StatusCode::FORBIDDEN, e),
            }
        }
        "/api/login/begin" => {
            let list = creds(state).unwrap_or_default();
            if list.is_empty() {
                return err(StatusCode::FORBIDDEN, "no passkey enrolled yet");
            }
            let key = new_challenge(state, random_bytes(32), Purpose::Login, None);
            let allow: Vec<Value> = list.iter().map(|c| json!({ "type": "public-key", "id": c.id })).collect();
            json_resp(StatusCode::OK, json!({ "publicKey": { "challenge": key, "rpId": state.rp.rp_id, "allowCredentials": allow, "userVerification": "required", "timeout": 120000 }}))
        }
        "/api/login/finish" | "/api/decide/finish" => {
            let Some(ch) = body.get("challenge").and_then(|c| c.as_str()).map(String::from) else { return err(StatusCode::BAD_REQUEST, "challenge required") };
            let Some(p) = take_challenge(state, &ch) else { return err(StatusCode::FORBIDDEN, "unknown, used or expired challenge") };
            let decision = path == "/api/decide/finish";
            match (&p.purpose, decision) {
                (Purpose::Login, false) => {}
                (Purpose::Decision { .. }, true) if p.session == sess.as_ref().map(|s| s.0.clone()) && matches!(&sess, Some((_, SessionKind::Operator { .. }))) => {}
                _ => return err(StatusCode::FORBIDDEN, "challenge was issued for something else"),
            }
            let (Some(id), Some(cdj), Some(ad), Some(sig)) = (body.get("id").and_then(|s| s.as_str()), field_b64(&body, "clientDataJSON"), field_b64(&body, "authenticatorData"), field_b64(&body, "signature")) else {
                return err(StatusCode::BAD_REQUEST, "id, clientDataJSON, authenticatorData and signature are required");
            };
            let Some(oc) = creds(state).unwrap_or_default().into_iter().find(|c| c.id == id) else { return err(StatusCode::FORBIDDEN, "unknown passkey") };
            let cred = Credential { id: unb64u(&oc.id).unwrap_or_default(), x: oc.x, y: oc.y, sign_count: oc.sign_count };
            let count = match state.rp.verify_assertion(&unb64u(&ch).unwrap_or_default(), &cred, &cdj, &ad, &sig) {
                Ok(c) => c,
                Err(e) => return err(StatusCode::FORBIDDEN, e),
            };
            let l = match Ledger::open(&ledger_path()) { Ok(l) => l, Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e) };
            let _ = l.touch_operator_credential(&oc.id, count);
            drop(l);
            if !decision {
                let cookie = set_session(state, SessionKind::Operator { cred: oc.id.clone() });
                return Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .header("set-cookie", cookie)
                    .body(Full::new(Bytes::from(json!({ "ok": format!("signed in with {}", oc.name) }).to_string())))
                    .expect("response");
            }
            let Purpose::Decision { decision_json, nonce, request, approve, uses, ttl_secs } = p.purpose else { unreachable!() };
            match apply(state, &request, approve, uses, ttl_secs, &oc, &decision_json, &nonce, &cdj, &ad, &sig) {
                Ok(msg) => json_resp(StatusCode::OK, json!({ "ok": msg })),
                Err(e) => err(StatusCode::CONFLICT, e),
            }
        }
        "/api/decide/begin" => {
            let Some((sid, SessionKind::Operator { .. })) = sess.clone() else { return err(StatusCode::UNAUTHORIZED, "sign in with your passkey") };
            let Some(id) = body.get("id").and_then(|s| s.as_str()) else { return err(StatusCode::BAD_REQUEST, "id required") };
            let approve = match body.get("decision").and_then(|s| s.as_str()) {
                Some("approve") => true,
                Some("deny") => false,
                _ => return err(StatusCode::BAD_REQUEST, "decision must be approve or deny"),
            };
            let unlimited = body.get("unlimited").and_then(|u| u.as_bool()).unwrap_or(false);
            let uses = if !approve || unlimited { None } else { Some(body.get("uses").and_then(|u| u.as_u64()).unwrap_or(1).clamp(1, 1000) as u32) };
            let ttl_secs = body.get("ttl_secs").and_then(|u| u.as_u64()).unwrap_or(600).clamp(30, 24 * 3600);
            let req = match Ledger::open(&ledger_path()).and_then(|l| l.request(id).map_err(Into::into)) {
                Ok(r) => r,
                Err(e) => return err(StatusCode::NOT_FOUND, e),
            };
            if req.status != "pending" {
                return err(StatusCode::CONFLICT, format!("{id} is {}, not pending", req.status));
            }
            // The exact decision the passkey will sign. Field order is fixed.
            let decision_json = json!({
                "v": 1, "tenant": state.tenant.0, "request": req.id, "run": req.run, "zone": req.zone,
                "method": req.method, "host": req.host, "path": req.path, "risk": req.risk,
                "decision": if approve { "approve" } else { "deny" },
                "uses": uses, "ttl_secs": if approve { Some(ttl_secs) } else { None },
            })
            .to_string();
            let nonce = random_bytes(16);
            let challenge = decision_challenge(&nonce, &decision_json).to_vec();
            let key = new_challenge(state, challenge, Purpose::Decision { decision_json: decision_json.clone(), nonce, request: req.id.clone(), approve, uses, ttl_secs }, Some(sid));
            let allow: Vec<Value> = creds(state).unwrap_or_default().iter().map(|c| json!({ "type": "public-key", "id": c.id })).collect();
            json_resp(StatusCode::OK, json!({
                "decision": serde_json::from_str::<Value>(&decision_json).unwrap_or(Value::Null),
                "publicKey": { "challenge": key, "rpId": state.rp.rp_id, "allowCredentials": allow, "userVerification": "required", "timeout": 120000 }
            }))
        }
        "/api/logout" => {
            if let Some(s) = sid {
                state.sessions.lock().expect("lock").remove(&s);
            }
            json_resp(StatusCode::OK, json!({ "ok": "signed out" }))
        }
        _ => resp(StatusCode::NOT_FOUND, "text/plain", "not found"),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply(state: &State, request: &str, approve: bool, uses: Option<u32>, ttl_secs: u64, oc: &OperatorCredential, decision_json: &str, nonce: &[u8], cdj: &[u8], ad: &[u8], sig: &[u8]) -> Result<String> {
    let mut l = Ledger::open(&ledger_path())?;
    let by = format!("passkey:{}", oc.name);
    let signed = json!({
        "credential": oc.id, "rp_id": state.rp.rp_id, "origin": state.rp.origin, "decision_json": decision_json, "nonce": b64u(nonce),
        "client_data_json": b64u(cdj), "authenticator_data": b64u(ad), "signature": b64u(sig),
    });
    if approve {
        let gid = l.approve(request, &Approval { uses, ttl: Duration::from_secs(ttl_secs), path_prefix: None, decided_by: by.clone() })?;
        l.audit(&state.tenant, None, "decision", &json!({ "request": request, "decision": "approve", "grant": gid, "by": by, "signed": signed }))?;
        Ok(format!("approved {request} → {gid} (signed with {})", oc.name))
    } else {
        l.deny(request, &by)?;
        l.audit(&state.tenant, None, "decision", &json!({ "request": request, "decision": "deny", "by": by, "signed": signed }))?;
        Ok(format!("denied {request} (signed with {})", oc.name))
    }
}

fn dashboard(state: &State) -> Result<Value> {
    let l = Ledger::open(&ledger_path())?;
    let t = &state.tenant;
    let audit: Vec<Value> = l
        .audit_tail(40)?
        .into_iter()
        .map(|(seq, ts, kind, run, body)| json!({ "seq": seq, "ts": ts, "kind": kind, "run": run, "body": serde_json::from_str::<Value>(&body).unwrap_or(Value::Null) }))
        .collect();
    Ok(json!({
        "now": wicket_store::now(),
        "tenant": t.0,
        "pending": l.pending(t)?,
        "decided": l.decided(t, 15)?,
        "runs": l.runs(t, 15)?,
        "passkeys": l.operator_credentials(t)?,
        "audit": audit,
    }))
}
