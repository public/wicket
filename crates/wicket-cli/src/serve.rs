//! `wicket serve`: the operator console (design §14.1.3, proof-of-concept cut), signed in and
//! driven with passkeys.
//!
//! Security flow:
//! 1. **Bootstrap.** At start-up, *only if no operator passkey exists yet*, a one-time enrolment link
//!    is printed. It is single-use, expires after 10 minutes, and the session it creates can do one
//!    thing: register a passkey. It cannot view runs or decide anything.
//! 2. **Sign-in** is a passkey assertion (user verification required) giving a 12-hour session.
//!    Adding further passkeys needs a signed-in operator.
//! 3. **Every action is a fresh passkey assertion** whose challenge is
//!    `sha256(nonce || canonical action JSON)`. The actions: approve or deny a request (its id,
//!    method, host, path, whether it is a prefix ask, decision, uses, lifetime and the agent's
//!    verified identity), start a run (the allowlisted manifest, its content digest, the task
//!    override, the run id and the principal it will carry), send a follow-up (run and text) and
//!    revoke an identity (run and reason). The server builds the JSON from its own reading of the
//!    ledger and disk at `begin`, keeps it with the challenge, and at `finish` verifies the signature,
//!    consumes the challenge (single use, 2-minute expiry, bound to the session that asked for it),
//!    re-checks what may have changed in between (the manifest's bytes, the run still running, the
//!    request still pending and its agent still verified), applies the action, and writes the signed
//!    triple (clientDataJSON, authenticatorData, signature) into the audit log, so
//!    `wicket audit --verify` re-verifies every console action offline.
//!
//! The browser never sends a path. Runs start only from manifests listed in an allowlisted
//! directory (see [`manifest_roots`]), named by root and file name.
//!
//! The console binds to loopback; WebAuthn needs a secure context, so open it as
//! http://localhost:PORT (or behind HTTPS on a tailnet with --origin/--rp-id). `wicket approve` on the
//! host remains a break-glass path and is audited as such.

use crate::{data_dir, ledger_path};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use wicket_auth::{b64u, decision_challenge, unb64u, Credential, RelyingParty};
use wicket_core::{Manifest, RunId, TenantId};
use wicket_store::{Approval, Ledger, OperatorCredential};

const PAGE: &str = include_str!("console.html");
const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const CHALLENGE_TTL: Duration = Duration::from_secs(120);
/// Longest follow-up or task override the console accepts (characters).
const MAX_TEXT: usize = 16 * 1024;
const MAX_REASON: usize = 500;

#[derive(Clone, PartialEq)]
enum SessionKind {
    Bootstrap,
    Operator { cred: String },
}

struct Session {
    kind: SessionKind,
    expires: Instant,
}

/// A console action, as the server resolved it at `begin`. Applied only with a passkey signature
/// over its canonical JSON.
#[derive(Clone, Debug, PartialEq)]
enum Action {
    Decide { request: String, approve: bool, uses: Option<u32>, ttl_secs: u64 },
    Say { run: String, text: String },
    Revoke { run: String, reason: String },
    Start { root: String, name: String, path: PathBuf, manifest_sha256: String, task: Option<String>, run: String, principal: Value },
}

enum Purpose {
    Register,
    Login,
    Action { action_json: String, nonce: Vec<u8>, action: Box<Action> },
}

struct Pending {
    purpose: Purpose,
    session: Option<String>,
    expires: Instant,
}

/// Starts a console run. The real one runs `wicket run` detached; tests record instead.
type Launcher = Box<dyn Fn(&Launch) -> Result<()> + Send + Sync>;
/// The verified identity of a run's agent (crate::verified_identity; replaceable in tests, which
/// have no issuer key).
type IdentityCheck = fn(&Ledger, &str) -> Value;

/// What the console asks the launcher to start.
#[derive(Clone, Debug)]
pub struct Launch {
    pub run: String,
    pub manifest: PathBuf,
    pub task: Option<String>,
    pub principal: Value,
    pub log: PathBuf,
}

struct State {
    rp: RelyingParty,
    tenant: TenantId,
    ledger: PathBuf,
    data: PathBuf,
    roots: Vec<(String, PathBuf)>,
    launcher: Launcher,
    identity: IdentityCheck,
    bootstrap: Mutex<Option<(String, Instant)>>,
    sessions: Mutex<HashMap<String, Session>>,
    challenges: Mutex<HashMap<String, Pending>>,
}

impl State {
    fn ledger(&self) -> Result<Ledger> {
        Ok(Ledger::open(&self.ledger)?)
    }
}

/// The directories the console may start runs from, by name: the installation's `manifests`
/// directory (`$WICKET_HOME/manifests`, default `~/.local/share/wicket/manifests`), and `examples/`
/// of the directory `wicket serve` was started in, if there is one. Only regular files directly in
/// them, named like `name.yaml`, are offered; symlinks and subdirectories are not.
pub fn manifest_roots() -> Vec<(String, PathBuf)> {
    let mut roots = vec![("manifests".to_string(), data_dir().join("manifests"))];
    if let Ok(ex) = std::env::current_dir().map(|d| d.join("examples")) {
        if ex.is_dir() {
            roots.push(("examples".to_string(), std::fs::canonicalize(&ex).unwrap_or(ex)));
        }
    }
    roots
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
    let exe = std::env::current_exe()?;
    let state = Arc::new(State {
        rp: RelyingParty { rp_id, origin: origin.clone() },
        tenant,
        ledger: ledger_path(),
        data: data_dir(),
        roots: manifest_roots(),
        launcher: Box::new(move |l| launch_detached(&exe, l)),
        identity: |l, run| crate::verified_identity(l, run, None),
        bootstrap: Mutex::new(None),
        sessions: Mutex::new(HashMap::new()),
        challenges: Mutex::new(HashMap::new()),
    });
    let listener = TcpListener::bind(addr).await?;
    println!("wicket console on {origin}/  (listening on {addr})");
    for (name, dir) in &state.roots {
        println!("runs can be started from {name}: {}", dir.display());
    }
    if has_passkeys {
        println!("sign in with your passkey. (Lost them all? On the host: wicket operator reset)");
    } else {
        let token = random_hex(24);
        *state.bootstrap.lock().expect("lock") = Some((token.clone(), Instant::now() + Duration::from_secs(600)));
        println!("no operator passkey yet. Enrol one within 10 minutes (single use):");
        println!("  {origin}/enrol?t={token}");
    }
    run_server(listener, state).await
}

async fn run_server(listener: TcpListener, state: Arc<State>) -> Result<()> {
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

/// Starts `wicket run` for a console launch as its own process (its own process group, so stopping
/// the console doesn't stop the run), logging to the run's directory. The run's principal is passed
/// in WICKET_PRINCIPAL (see crate::cli_principal).
fn launch_detached(exe: &std::path::Path, l: &Launch) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let log = std::fs::File::create(&l.log).with_context(|| format!("creating {}", l.log.display()))?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["run", "--run-id", &l.run]);
    if let Some(t) = &l.task {
        cmd.arg("--task").arg(t);
    }
    cmd.arg(&l.manifest)
        .env("WICKET_PRINCIPAL", l.principal.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .process_group(0);
    let mut child = cmd.spawn().context("starting wicket run")?;
    // Reap it when it exits; the console doesn't wait for it.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
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
        .header(
            "content-security-policy",
            "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
        )
        .body(Full::new(body.into()))
        .expect("response")
}

/// A JSON answer from a POST handler (and the session cookie, for sign-in).
#[derive(Debug)]
struct Reply {
    status: StatusCode,
    body: Value,
    cookie: Option<String>,
}

fn ok(body: Value) -> Reply {
    Reply { status: StatusCode::OK, body, cookie: None }
}

fn err(status: StatusCode, msg: impl std::fmt::Display) -> Reply {
    Reply { status, body: json!({ "error": msg.to_string() }), cookie: None }
}

fn to_response(r: Reply) -> Response<Full<Bytes>> {
    let mut out = resp(r.status, "application/json", r.body.to_string());
    if let Some(c) = r.cookie {
        out.headers_mut().insert("set-cookie", c.parse().expect("cookie header"));
    }
    out
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
    Ok(state.ledger()?.operator_credentials(&state.tenant)?)
}

async fn json_body(req: Request<Incoming>) -> Option<Value> {
    let b = Limited::new(req.into_body(), 64 * 1024).collect().await.ok()?.to_bytes();
    serde_json::from_slice(&b).ok()
}

fn field_b64(v: &Value, k: &str) -> Option<Vec<u8>> {
    v.get(k).and_then(|s| s.as_str()).and_then(|s| unb64u(s).ok())
}

fn assertion_options(state: &State, key: &str) -> Value {
    let allow: Vec<Value> = creds(state).unwrap_or_default().iter().map(|c| json!({ "type": "public-key", "id": c.id })).collect();
    json!({ "challenge": key, "rpId": state.rp.rp_id, "allowCredentials": allow, "userVerification": "required", "timeout": 120000 })
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
                Response::builder()
                    .status(StatusCode::SEE_OTHER)
                    .header("location", "/")
                    .header("set-cookie", cookie)
                    .body(Full::new(Bytes::new()))
                    .expect("response")
            }
            "/api/me" => {
                let n = creds(state).map(|c| c.len()).unwrap_or(0);
                let who = match session(state, &sid) {
                    Some((_, SessionKind::Operator { cred })) => json!({ "state": "operator", "credential": cred }),
                    Some((_, SessionKind::Bootstrap)) => json!({ "state": "bootstrap" }),
                    None => json!({ "state": "none" }),
                };
                to_response(ok(json!({ "who": who, "passkeys": n, "rp_id": state.rp.rp_id })))
            }
            "/api/state" => match session(state, &sid) {
                Some((_, SessionKind::Operator { .. })) => match dashboard(state) {
                    Ok(v) => to_response(ok(v)),
                    Err(e) => to_response(err(StatusCode::INTERNAL_SERVER_ERROR, e)),
                },
                _ => to_response(err(StatusCode::UNAUTHORIZED, "sign in with your passkey")),
            },
            _ => resp(StatusCode::NOT_FOUND, "text/plain", "not found"),
        };
    }
    if method != Method::POST {
        return resp(StatusCode::METHOD_NOT_ALLOWED, "text/plain", "method not allowed");
    }
    // Every POST: the custom header (no cross-site form or simple request can send it).
    if req.headers().get("x-wicket-csrf").map(|v| v.as_bytes()) != Some(b"1") {
        return to_response(err(StatusCode::FORBIDDEN, "missing x-wicket-csrf header"));
    }
    let Some(body) = json_body(req).await else {
        return to_response(err(StatusCode::BAD_REQUEST, "bad JSON body"));
    };
    match post(state, &path, &sid, &body) {
        Some(r) => to_response(r),
        None => resp(StatusCode::NOT_FOUND, "text/plain", "not found"),
    }
}

/// Every POST endpoint, after the CSRF header check and body parsing. None: no such endpoint.
fn post(state: &State, path: &str, sid: &Option<String>, body: &Value) -> Option<Reply> {
    let sess = session(state, sid);
    Some(match path {
        "/api/register/begin" => register_begin(state, &sess),
        "/api/register/finish" => register_finish(state, &sess, body),
        "/api/login/begin" => {
            let list = creds(state).unwrap_or_default();
            if list.is_empty() {
                return Some(err(StatusCode::FORBIDDEN, "no passkey enrolled yet"));
            }
            let key = new_challenge(state, random_bytes(32), Purpose::Login, None);
            ok(json!({ "publicKey": assertion_options(state, &key) }))
        }
        "/api/login/finish" => login_finish(state, body),
        // `/api/decide/*` is the older name for the approve/deny action.
        "/api/action/begin" | "/api/decide/begin" => {
            let mut body = body.clone();
            if path == "/api/decide/begin" {
                let Some(o) = body.as_object_mut() else { return Some(err(StatusCode::BAD_REQUEST, "body must be a JSON object")) };
                o.insert("action".into(), "decide".into());
            }
            action_begin(state, &sess, &body)
        }
        "/api/action/finish" | "/api/decide/finish" => action_finish(state, &sess, body),
        "/api/logout" => {
            if let Some(s) = sid {
                state.sessions.lock().expect("lock").remove(s);
            }
            ok(json!({ "ok": "signed out" }))
        }
        _ => return None,
    })
}

fn register_begin(state: &State, sess: &Option<(String, SessionKind)>) -> Reply {
    // Bootstrap sessions may enrol only while no passkey exists; afterwards a signed-in operator must.
    let n = creds(state).map(|c| c.len()).unwrap_or(0);
    let allowed = matches!(sess, Some((_, SessionKind::Operator { .. }))) || (matches!(sess, Some((_, SessionKind::Bootstrap))) && n == 0);
    if !allowed {
        return err(StatusCode::FORBIDDEN, "enrolling a passkey needs the enrolment link (first passkey) or a signed-in operator");
    }
    let challenge = random_bytes(32);
    let key = new_challenge(state, challenge.clone(), Purpose::Register, sess.as_ref().map(|s| s.0.clone()));
    let exclude: Vec<Value> = creds(state).unwrap_or_default().iter().map(|c| json!({ "type": "public-key", "id": c.id })).collect();
    ok(json!({ "publicKey": {
        "challenge": key,
        "rp": { "id": state.rp.rp_id, "name": "wicket" },
        "user": { "id": b64u(format!("operator-{}", state.tenant).as_bytes()), "name": "operator", "displayName": "wicket operator" },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        "authenticatorSelection": { "residentKey": "required", "userVerification": "required" },
        "attestation": "none", "timeout": 120000, "excludeCredentials": exclude
    }}))
}

fn register_finish(state: &State, sess: &Option<(String, SessionKind)>, body: &Value) -> Reply {
    let (Some(ch), Some(cdj), Some(att)) =
        (body.get("challenge").and_then(|c| c.as_str()), field_b64(body, "clientDataJSON"), field_b64(body, "attestationObject"))
    else {
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
            let l = match state.ledger() {
                Ok(l) => l,
                Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
            };
            if let Err(e) = l.add_operator_credential(&state.tenant, &oc) {
                return err(StatusCode::CONFLICT, e);
            }
            let _ = l.audit(&state.tenant, None, "operator.passkey_added", &json!({ "credential": oc.id, "name": oc.name, "via": if matches!(sess, Some((_, SessionKind::Bootstrap))) { "enrolment link" } else { "signed-in operator" } }));
            // The enrolment session has done its one job: end it, so the next step is a real sign-in.
            if let Some((sid, SessionKind::Bootstrap)) = sess {
                state.sessions.lock().expect("lock").remove(sid);
            }
            ok(json!({ "ok": "passkey registered; now sign in with it" }))
        }
        Err(e) => err(StatusCode::FORBIDDEN, e),
    }
}

/// The verified parts of a passkey assertion: the operator's credential and the signed triple.
struct Asserted {
    oc: OperatorCredential,
    cdj: Vec<u8>,
    ad: Vec<u8>,
    sig: Vec<u8>,
}

/// Verifies an assertion over `challenge` by one of the operator's passkeys and records its counter.
fn verify_assertion(state: &State, challenge: &str, body: &Value) -> Result<Asserted, Reply> {
    let (Some(id), Some(cdj), Some(ad), Some(sig)) = (
        body.get("id").and_then(|s| s.as_str()),
        field_b64(body, "clientDataJSON"),
        field_b64(body, "authenticatorData"),
        field_b64(body, "signature"),
    ) else {
        return Err(err(StatusCode::BAD_REQUEST, "id, clientDataJSON, authenticatorData and signature are required"));
    };
    let Some(oc) = creds(state).unwrap_or_default().into_iter().find(|c| c.id == id) else {
        return Err(err(StatusCode::FORBIDDEN, "unknown passkey"));
    };
    let cred = Credential { id: unb64u(&oc.id).unwrap_or_default(), x: oc.x, y: oc.y, sign_count: oc.sign_count };
    let count = state
        .rp
        .verify_assertion(&unb64u(challenge).unwrap_or_default(), &cred, &cdj, &ad, &sig)
        .map_err(|e| err(StatusCode::FORBIDDEN, e))?;
    let l = state.ledger().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let _ = l.touch_operator_credential(&oc.id, count);
    Ok(Asserted { oc, cdj, ad, sig })
}

fn login_finish(state: &State, body: &Value) -> Reply {
    let Some(ch) = body.get("challenge").and_then(|c| c.as_str()) else { return err(StatusCode::BAD_REQUEST, "challenge required") };
    let Some(p) = take_challenge(state, ch) else { return err(StatusCode::FORBIDDEN, "unknown, used or expired challenge") };
    if !matches!(p.purpose, Purpose::Login) {
        return err(StatusCode::FORBIDDEN, "challenge was issued for something else");
    }
    let a = match verify_assertion(state, ch, body) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let cookie = set_session(state, SessionKind::Operator { cred: a.oc.id.clone() });
    Reply { status: StatusCode::OK, body: json!({ "ok": format!("signed in with {}", a.oc.name) }), cookie: Some(cookie) }
}

/// The principal of a run started from the console: the passkey-authenticated operator (the
/// console analogue of crate::cli_principal). Which passkey it was is recorded alongside.
pub fn console_principal(oc: &OperatorCredential) -> Value {
    json!({ "type": "human", "id": format!("passkey:{}", oc.name), "via": "console", "assurance": "passkey (user verification)", "credential": oc.id })
}

fn str_field<'a>(body: &'a Value, k: &str) -> Option<&'a str> {
    body.get(k).and_then(|s| s.as_str())
}

/// Resolves an allowlisted manifest: a root by name and a plain file name in it (no separators, no
/// dot-files, `.yaml`/`.yml`), which must be a regular file (not a symlink). Returns its path and bytes.
fn resolve_manifest(state: &State, root: &str, name: &str) -> Result<(PathBuf, Vec<u8>)> {
    let ok_name = name.len() <= 128
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && !name.contains("..")
        && (name.ends_with(".yaml") || name.ends_with(".yml"));
    if !ok_name {
        bail!("{name:?} is not a manifest file name (letters, digits, '.', '_', '-'; ending .yaml or .yml)");
    }
    let Some((_, dir)) = state.roots.iter().find(|(r, _)| r == root) else {
        bail!(
            "{root:?} is not a directory runs can be started from (have: {})",
            state.roots.iter().map(|r| r.0.as_str()).collect::<Vec<_>>().join(", ")
        );
    };
    let path = dir.join(name);
    let meta = std::fs::symlink_metadata(&path).with_context(|| format!("{root}/{name}"))?;
    if !meta.file_type().is_file() {
        bail!("{root}/{name} is not a regular file");
    }
    let bytes = std::fs::read(&path)?;
    Ok((path, bytes))
}

fn list_manifests(state: &State) -> Vec<Value> {
    let mut out = Vec::new();
    for (root, dir) in &state.roots {
        let Ok(rd) = std::fs::read_dir(dir) else { continue };
        let mut names: Vec<String> = rd.filter_map(|e| e.ok()).filter_map(|e| e.file_name().into_string().ok()).collect();
        names.sort();
        for name in names {
            if let Ok((_, bytes)) = resolve_manifest(state, root, &name) {
                let m = std::str::from_utf8(&bytes).ok().and_then(|t| Manifest::from_yaml(t).ok());
                out.push(json!({
                    "root": root, "name": name,
                    "agent": m.as_ref().and_then(|m| m.agent.as_ref().map(|a| a.name.clone())),
                    "program": m.as_ref().and_then(|m| m.program.as_ref().map(|p| p.name.clone())),
                    "zone": m.as_ref().map(|m| m.zone.name.clone()),
                    "valid": m.is_some(),
                }));
            }
        }
    }
    out
}

/// Resolves and checks an action at `begin`, and builds the exact JSON the passkey will sign.
fn build_action(state: &State, oc: &OperatorCredential, body: &Value) -> Result<(Action, Value), Reply> {
    let l = state.ledger().map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let bad = |m: &str| err(StatusCode::BAD_REQUEST, m);
    match str_field(body, "action") {
        Some("decide") => {
            let Some(id) = str_field(body, "id") else { return Err(bad("id required")) };
            let approve = match str_field(body, "decision") {
                Some("approve") => true,
                Some("deny") => false,
                _ => return Err(bad("decision must be approve or deny")),
            };
            let unlimited = body.get("unlimited").and_then(|u| u.as_bool()).unwrap_or(false);
            let uses = if !approve || unlimited {
                None
            } else {
                Some(body.get("uses").and_then(|u| u.as_u64()).unwrap_or(1).clamp(1, 1000) as u32)
            };
            let ttl_secs = body.get("ttl_secs").and_then(|u| u.as_u64()).unwrap_or(600).clamp(30, 24 * 3600);
            let req = l.request(id).map_err(|e| err(StatusCode::NOT_FOUND, e))?;
            if req.status != "pending" {
                return Err(err(StatusCode::CONFLICT, format!("{id} is {}, not pending", req.status)));
            }
            let identity = (state.identity)(&l, &req.run);
            if approve && !identity_approvable(&identity) {
                return Err(err(
                    StatusCode::CONFLICT,
                    format!("{id}: the requesting agent's identity does not verify; it can be denied, not approved"),
                ));
            }
            // The exact decision the passkey will sign. Field order is fixed.
            let v = json!({
                "v": 1, "action": "decide", "tenant": state.tenant.0, "request": req.id, "run": req.run, "zone": req.zone,
                "method": req.method, "host": req.host, "path": req.path, "risk": req.risk,
                // A prefix ask (request_access with scope prefix) is granted as every path under `path`.
                "prefix": req.scope_prefix,
                "decision": if approve { "approve" } else { "deny" },
                "uses": uses, "ttl_secs": if approve { Some(ttl_secs) } else { None },
                // Who the human was told this is for; the passkey signs it with the decision: the
                // agent's verified identity (bound by its document's digest) and, inside its box,
                // which subagent reportedly asked.
                "agent": identity.get("id"), "identity_sha256": identity.get("identity_sha256"),
                "identity_verified": identity.get("verified"),
                "requested_by": req.attribution.iter().flat_map(wicket_proxy::attributed_agents).collect::<Vec<_>>(),
            });
            Ok((Action::Decide { request: req.id, approve, uses, ttl_secs }, v))
        }
        Some("say") => {
            let (Some(run), Some(text)) = (str_field(body, "run"), str_field(body, "text")) else {
                return Err(bad("run and text required"));
            };
            if text.trim().is_empty() {
                return Err(bad("nothing to say"));
            }
            if text.chars().count() > MAX_TEXT {
                return Err(bad("the message is too long"));
            }
            check_running(&l, run)?;
            let identity = (state.identity)(&l, run);
            let v = json!({
                "v": 1, "action": "say", "tenant": state.tenant.0, "run": run, "text": text,
                "agent": identity.get("id"), "identity_sha256": identity.get("identity_sha256"),
            });
            Ok((Action::Say { run: run.into(), text: text.into() }, v))
        }
        Some("revoke") => {
            let Some(run) = str_field(body, "run") else { return Err(bad("run required")) };
            let reason = str_field(body, "reason").map(str::trim).filter(|r| !r.is_empty()).unwrap_or("revoked by the operator");
            if reason.chars().count() > MAX_REASON {
                return Err(bad("the reason is too long"));
            }
            let Some(row) = l.identity(run).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))? else {
                return Err(err(StatusCode::NOT_FOUND, format!("no identity was issued for {run}")));
            };
            if row.tenant != state.tenant.0 {
                return Err(err(StatusCode::NOT_FOUND, format!("no identity was issued for {run}")));
            }
            let v = json!({
                "v": 1, "action": "revoke", "tenant": state.tenant.0, "run": run, "reason": reason,
                "agent": row.spiffe_id, "zone": row.zone,
            });
            Ok((Action::Revoke { run: run.into(), reason: reason.into() }, v))
        }
        Some("start_run") => {
            let (Some(root), Some(name)) = (str_field(body, "root"), str_field(body, "manifest")) else {
                return Err(bad("root and manifest required"));
            };
            let task = str_field(body, "task").filter(|t| !t.trim().is_empty()).map(String::from);
            if task.as_ref().is_some_and(|t| t.chars().count() > MAX_TEXT) {
                return Err(bad("the task is too long"));
            }
            let (path, bytes) = resolve_manifest(state, root, name).map_err(|e| err(StatusCode::FORBIDDEN, format!("{e:#}")))?;
            let text = std::str::from_utf8(&bytes).map_err(|_| bad("the manifest is not UTF-8"))?;
            let m = Manifest::from_yaml(text).map_err(|e| err(StatusCode::BAD_REQUEST, format!("{root}/{name}: {e}")))?;
            if task.is_some() && m.agent.is_none() {
                return Err(bad("a task override applies to agent manifests only"));
            }
            if m.tenant != state.tenant {
                return Err(err(StatusCode::FORBIDDEN, "the manifest is for another tenant"));
            }
            let manifest_sha256 = hex::encode(sha2::Sha256::digest(&bytes));
            let run = RunId::new().0;
            let principal = console_principal(oc);
            let v = json!({
                "v": 1, "action": "start_run", "tenant": state.tenant.0, "root": root, "manifest": name,
                "manifest_sha256": manifest_sha256, "task": task, "run": run,
                "agent": m.agent.as_ref().map(|a| a.name.clone()), "program": m.program.as_ref().map(|p| p.name.clone()),
                "zone": m.zone.name, "principal": principal,
            });
            Ok((Action::Start { root: root.into(), name: name.into(), path, manifest_sha256, task, run, principal }, v))
        }
        _ => Err(bad("action must be decide, say, revoke or start_run")),
    }
}

/// Whether a request's agent may be approved for: its identity verifies (programs have none; that's fine).
fn identity_approvable(identity: &Value) -> bool {
    identity.get("verified").and_then(|v| v.as_bool()) == Some(true)
        || identity.get("error").and_then(|e| e.as_str()).unwrap_or("").starts_with("no identity was issued")
}

fn check_running(l: &Ledger, run: &str) -> Result<(), Reply> {
    match l.run_status(run).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e))?.as_deref() {
        Some("running") => {}
        Some(s) => return Err(err(StatusCode::CONFLICT, format!("{run} is {s}, not running"))),
        None => return Err(err(StatusCode::NOT_FOUND, format!("no run {run}"))),
    }
    if let Ok(Some((r, ..))) = l.revoked_in_chain(run) {
        return Err(err(StatusCode::CONFLICT, format!("{run}'s identity is revoked (via {r})")));
    }
    Ok(())
}

fn action_begin(state: &State, sess: &Option<(String, SessionKind)>, body: &Value) -> Reply {
    let Some((sid, SessionKind::Operator { cred })) = sess.clone() else {
        return err(StatusCode::UNAUTHORIZED, "sign in with your passkey");
    };
    let Some(oc) = creds(state).unwrap_or_default().into_iter().find(|c| c.id == cred) else {
        return err(StatusCode::UNAUTHORIZED, "the passkey you signed in with is no longer enrolled");
    };
    let (action, v) = match build_action(state, &oc, body) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let action_json = v.to_string();
    let nonce = random_bytes(16);
    let challenge = decision_challenge(&nonce, &action_json).to_vec();
    let key = new_challenge(state, challenge, Purpose::Action { action_json, nonce, action: Box::new(action) }, Some(sid));
    // `decision` is the older name the page used for the signed JSON.
    ok(json!({ "action": v, "decision": v, "publicKey": assertion_options(state, &key) }))
}

fn action_finish(state: &State, sess: &Option<(String, SessionKind)>, body: &Value) -> Reply {
    let Some(ch) = body.get("challenge").and_then(|c| c.as_str()) else { return err(StatusCode::BAD_REQUEST, "challenge required") };
    let Some(p) = take_challenge(state, ch) else { return err(StatusCode::FORBIDDEN, "unknown, used or expired challenge") };
    let same_session = p.session.is_some() && p.session == sess.as_ref().map(|s| s.0.clone());
    let Purpose::Action { action_json, nonce, action } = p.purpose else {
        return err(StatusCode::FORBIDDEN, "challenge was issued for something else");
    };
    if !same_session || !matches!(sess, Some((_, SessionKind::Operator { .. }))) {
        return err(StatusCode::FORBIDDEN, "challenge was issued for something else");
    }
    let a = match verify_assertion(state, ch, body) {
        Ok(a) => a,
        Err(r) => return r,
    };
    let mut signed = json!({
        "credential": a.oc.id, "rp_id": state.rp.rp_id, "origin": state.rp.origin,
        "nonce": b64u(&nonce), "client_data_json": b64u(&a.cdj), "authenticator_data": b64u(&a.ad), "signature": b64u(&a.sig),
    });
    // Decisions keep the field name they have always had, so older records and verifiers agree.
    let field = if matches!(*action, Action::Decide { .. }) { "decision_json" } else { "action_json" };
    signed[field] = action_json.into();
    match apply(state, &action, &a.oc, signed) {
        Ok(msg) => ok(json!({ "ok": msg })),
        Err(e) => err(StatusCode::CONFLICT, format!("{e:#}")),
    }
}

/// Applies a signed action and audits it with the operator's passkey and the signed triple.
fn apply(state: &State, action: &Action, oc: &OperatorCredential, signed: Value) -> Result<String> {
    let mut l = state.ledger()?;
    let by = format!("passkey:{}", oc.name);
    let t = &state.tenant;
    let rid = |r: &str| RunId(r.to_string());
    match action {
        Action::Decide { request, approve: true, uses, ttl_secs } => {
            // The agent may have been revoked since the operator was shown it.
            let req = l.request(request)?;
            if !identity_approvable(&(state.identity)(&l, &req.run)) {
                bail!("{request}: the requesting agent's identity no longer verifies; it can be denied, not approved");
            }
            let gid = l.approve(
                request,
                &Approval { uses: *uses, ttl: Duration::from_secs(*ttl_secs), path_prefix: None, decided_by: by.clone() },
            )?;
            l.audit(
                t,
                None,
                "decision",
                &json!({ "action": "decide", "request": request, "decision": "approve", "grant": gid, "prefix": req.scope_prefix, "by": by, "signed": signed }),
            )?;
            let scope = if req.scope_prefix { format!(" for every path under {}{}", req.host, req.path) } else { String::new() };
            Ok(format!("approved {request} → {gid}{scope} (signed with {})", oc.name))
        }
        Action::Decide { request, approve: false, .. } => {
            l.deny(request, &by)?;
            l.audit(
                t,
                None,
                "decision",
                &json!({ "action": "decide", "request": request, "decision": "deny", "by": by, "signed": signed }),
            )?;
            Ok(format!("denied {request} (signed with {})", oc.name))
        }
        Action::Say { run, text } => {
            check_running(&l, run).map_err(|r| anyhow::anyhow!("{}", r.body["error"].as_str().unwrap_or("not running")))?;
            l.add_operator_message(run, text, &by)?;
            l.audit(
                t,
                Some(&rid(run)),
                "operator.message",
                &json!({ "action": "say", "run": run, "by": by, "via": "console", "chars": text.len(), "signed": signed }),
            )?;
            Ok(format!("queued for {run}: the agent gets it as its next turn (signed with {})", oc.name))
        }
        Action::Revoke { run, reason } => {
            let fresh = l.revoke(run, &by, reason)?;
            l.audit(
                t,
                Some(&rid(run)),
                "identity.revoked",
                &json!({ "action": "revoke", "run": run, "by": by, "via": "console", "reason": reason, "signed": signed }),
            )?;
            Ok(format!(
                "{} {run}: its runner stops the box within seconds; its messages and approvals are refused (signed with {})",
                if fresh { "revoked" } else { "already revoked" },
                oc.name
            ))
        }
        Action::Start { root, name, path, manifest_sha256, task, run, principal } => {
            // Start exactly what was signed: the same allowlisted file with the same bytes.
            let (now_path, bytes) = resolve_manifest(state, root, name)?;
            if now_path != *path || hex::encode(sha2::Sha256::digest(&bytes)) != *manifest_sha256 {
                bail!("{root}/{name} changed after you were shown it; start it again");
            }
            let dir = state.data.join("runs").join(run);
            std::fs::create_dir_all(&dir)?;
            let log = dir.join("console.log");
            l.audit(
                t,
                Some(&rid(run)),
                "run.console_start",
                &json!({ "action": "start_run", "run": run, "root": root, "manifest": name, "manifest_sha256": manifest_sha256,
                         "task": task, "principal": principal, "by": by, "signed": signed }),
            )?;
            drop(l);
            (state.launcher)(&Launch {
                run: run.clone(),
                manifest: path.clone(),
                task: task.clone(),
                principal: principal.clone(),
                log: log.clone(),
            })?;
            Ok(format!("started {run} from {root}/{name} as {} (log: runs/{run}/console.log)", wicket_identity::principal_label(principal)))
        }
    }
}

fn dashboard(state: &State) -> Result<Value> {
    let l = state.ledger()?;
    let t = &state.tenant;
    let audit: Vec<Value> = l
        .audit_tail(40)?
        .into_iter()
        .map(|(seq, ts, kind, run, body)| json!({ "seq": seq, "ts": ts, "kind": kind, "run": run, "body": serde_json::from_str::<Value>(&body).unwrap_or(Value::Null) }))
        .collect();
    let runs: Vec<Value> = l
        .runs(t, 15)?
        .into_iter()
        .map(|r| {
            let mut v = serde_json::to_value(&r).unwrap_or(Value::Null);
            let id = v.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
            v["has_identity"] = l.identity(&id).ok().flatten().is_some().into();
            v["revoked"] = l.revoked(&id).ok().flatten().is_some().into();
            v
        })
        .collect();
    Ok(json!({
        "now": wicket_store::now(),
        "tenant": t.0,
        "pending": l.pending(t)?.into_iter().map(|r| {
            let mut v = serde_json::to_value(&r).unwrap_or(Value::Null);
            v["identity"] = (state.identity)(&l, &r.run);
            v
        }).collect::<Vec<_>>(),
        "decided": l.decided(t, 15)?,
        "runs": runs,
        "manifests": list_manifests(state),
        "passkeys": l.operator_credentials(t)?,
        "audit": audit,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    const ORIGIN: &str = "http://localhost:8787";

    struct T {
        state: State,
        key: SigningKey,
        cred: String,
        sid: Option<String>,
        count: u32,
        launched: Arc<Mutex<Vec<Launch>>>,
        dir: PathBuf,
    }

    /// Tests have no issuer key: a run with an identity row named "bad-…" doesn't verify; others do.
    fn fake_identity(l: &Ledger, run: &str) -> Value {
        match l.identity(run) {
            Ok(Some(r)) if r.agent.starts_with("bad") => json!({ "verified": false, "run": run, "error": "signature invalid" }),
            Ok(Some(r)) => json!({ "verified": true, "id": r.spiffe_id, "agent": r.agent, "identity_sha256": "ab" }),
            _ => json!({ "verified": false, "run": run, "error": "no identity was issued for this run" }),
        }
    }

    fn setup(tag: &str) -> T {
        let dir = std::env::temp_dir().join(format!("wicket-serve-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("manifests")).unwrap();
        std::fs::create_dir_all(dir.join("elsewhere")).unwrap();
        let key = SigningKey::random(&mut rand_core::OsRng);
        let p = key.verifying_key().to_encoded_point(false);
        let cred = b64u(b"cred-1");
        let ledger = dir.join("ledger.db");
        let l = Ledger::open(&ledger).unwrap();
        l.add_operator_credential(
            &TenantId::single(),
            &OperatorCredential {
                id: cred.clone(),
                name: "laptop".into(),
                x: p.x().unwrap().as_slice().try_into().unwrap(),
                y: p.y().unwrap().as_slice().try_into().unwrap(),
                sign_count: 0,
            },
        )
        .unwrap();
        let launched = Arc::new(Mutex::new(Vec::new()));
        let rec = launched.clone();
        let state = State {
            rp: RelyingParty { rp_id: "localhost".into(), origin: ORIGIN.into() },
            tenant: TenantId::single(),
            ledger,
            data: dir.clone(),
            roots: vec![("manifests".into(), dir.join("manifests"))],
            launcher: Box::new(move |l| {
                rec.lock().unwrap().push(l.clone());
                Ok(())
            }),
            identity: fake_identity,
            bootstrap: Mutex::new(None),
            sessions: Mutex::new(HashMap::new()),
            challenges: Mutex::new(HashMap::new()),
        };
        let sid = random_hex(8);
        state
            .sessions
            .lock()
            .unwrap()
            .insert(sid.clone(), Session { kind: SessionKind::Operator { cred: cred.clone() }, expires: Instant::now() + SESSION_TTL });
        T { state, key, cred, sid: Some(sid), count: 0, launched, dir }
    }

    impl T {
        fn ledger(&self) -> Ledger {
            self.state.ledger().unwrap()
        }

        fn post(&self, path: &str, body: Value) -> Reply {
            post(&self.state, path, &self.sid, &body).expect("endpoint")
        }

        fn begin(&self, body: Value) -> Reply {
            self.post("/api/action/begin", body)
        }

        /// What a browser returns from navigator.credentials.get for `challenge` (base64url).
        fn sign(&mut self, challenge: &str) -> Value {
            self.count += 1;
            let cdj =
                json!({ "type": "webauthn.get", "challenge": challenge, "origin": ORIGIN, "crossOrigin": false }).to_string().into_bytes();
            let mut ad = sha2::Sha256::digest(b"localhost").to_vec();
            ad.push(0x01 | 0x04); // user present, user verified
            ad.extend_from_slice(&self.count.to_be_bytes());
            let mut msg = ad.clone();
            msg.extend_from_slice(&sha2::Sha256::digest(&cdj));
            let sig: Signature = self.key.sign(&msg);
            json!({ "challenge": challenge, "id": self.cred, "clientDataJSON": b64u(&cdj), "authenticatorData": b64u(&ad), "signature": b64u(sig.to_der().as_bytes()) })
        }

        /// Begins an action, signs its challenge and finishes it.
        fn act(&mut self, body: Value) -> Reply {
            let b = self.begin(body);
            assert_eq!(b.status, StatusCode::OK, "{:?}", b.body);
            let ch = b.body["publicKey"]["challenge"].as_str().unwrap().to_string();
            let a = self.sign(&ch);
            self.post("/api/action/finish", a)
        }

        fn running(&self, run: &str, agent: &str) {
            let l = self.ledger();
            l.run_started(&TenantId::single(), &RunId(run.into()), "z", agent).unwrap();
            l.put_identity(&wicket_store::IdentityRow {
                run: run.into(),
                tenant: TenantId::single().0,
                spiffe_id: format!("spiffe://wicket.local/t/{agent}"),
                zone: "z".into(),
                agent: agent.into(),
                parent_run: None,
                accept_from: vec![],
                jws: "x.y.z".into(),
                issued_at: wicket_store::now(),
            })
            .unwrap();
        }

        fn audit_kinds(&self) -> Vec<(String, Value)> {
            self.ledger().audit_tail(100).unwrap().into_iter().map(|(_, _, k, _, b)| (k, serde_json::from_str(&b).unwrap())).collect()
        }
    }

    fn assert_refused(r: &Reply, status: StatusCode, msg: &str) {
        assert_eq!(r.status, status, "{:?}", r.body);
        let e = r.body["error"].as_str().unwrap_or("");
        assert!(e.contains(msg), "{e:?} should mention {msg:?}");
    }

    #[test]
    fn say_queues_a_signed_operator_message() {
        let mut t = setup("say");
        t.running("run_a", "lead");
        let r = t.act(json!({ "action": "say", "run": "run_a", "text": "also check the tests" }));
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        let msgs = t.ledger().take_operator_messages("run_a").unwrap();
        assert_eq!(msgs, vec![("also check the tests".to_string(), "passkey:laptop".to_string())]);
        let (kind, body) = t.audit_kinds().pop().unwrap();
        assert_eq!(kind, "operator.message");
        assert_eq!(body["by"], "passkey:laptop");
        let signed: Value = serde_json::from_str(body["signed"]["action_json"].as_str().unwrap()).unwrap();
        assert_eq!(
            (signed["action"].as_str(), signed["run"].as_str(), signed["text"].as_str()),
            (Some("say"), Some("run_a"), Some("also check the tests"))
        );
        assert_eq!(crate::verify_signed_decisions(&t.ledger()).unwrap(), (1, 0), "re-verifies offline");
        // Not to a run that isn't running.
        assert_refused(&t.begin(json!({ "action": "say", "run": "run_nope", "text": "hi" })), StatusCode::NOT_FOUND, "no run");
        t.ledger().run_ended(&RunId("run_a".into()), "done", "").unwrap();
        assert_refused(&t.begin(json!({ "action": "say", "run": "run_a", "text": "hi" })), StatusCode::CONFLICT, "not running");
    }

    #[test]
    fn revoke_records_a_signed_revocation() {
        let mut t = setup("revoke");
        t.running("run_b", "lead");
        let r = t.act(json!({ "action": "revoke", "run": "run_b", "reason": "box may be compromised" }));
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        let (_, by, reason) = t.ledger().revoked("run_b").unwrap().unwrap();
        assert_eq!((by.as_str(), reason.as_str()), ("passkey:laptop", "box may be compromised"));
        let (kind, body) = t.audit_kinds().pop().unwrap();
        assert_eq!(kind, "identity.revoked");
        assert!(body["signed"]["signature"].is_string());
        assert_refused(&t.begin(json!({ "action": "revoke", "run": "run_none" })), StatusCode::NOT_FOUND, "no identity");
        // A revoked agent gets no follow-ups.
        assert_refused(&t.begin(json!({ "action": "say", "run": "run_b", "text": "hi" })), StatusCode::CONFLICT, "revoked");
    }

    #[test]
    fn every_action_needs_a_signed_in_operator_and_a_valid_signature() {
        let mut t = setup("unsigned");
        t.running("run_c", "lead");
        let say = json!({ "action": "say", "run": "run_c", "text": "hi" });
        // No session (or a bootstrap one): no challenge.
        assert_refused(&post(&t.state, "/api/action/begin", &None, &say).unwrap(), StatusCode::UNAUTHORIZED, "sign in");
        // No assertion at all.
        let b = t.begin(say.clone());
        let ch = b.body["publicKey"]["challenge"].as_str().unwrap().to_string();
        assert_refused(&t.post("/api/action/finish", json!({ "challenge": ch })), StatusCode::BAD_REQUEST, "required");
        // That consumed it: even a good signature now is refused.
        let a = t.sign(&ch);
        assert_refused(&t.post("/api/action/finish", a), StatusCode::FORBIDDEN, "unknown, used or expired");
        // A signature by another key.
        let b = t.begin(say.clone());
        let ch = b.body["publicKey"]["challenge"].as_str().unwrap().to_string();
        let mut a = t.sign(&ch);
        t.key = SigningKey::random(&mut rand_core::OsRng);
        let forged = t.sign(&ch);
        a["signature"] = forged["signature"].clone();
        a["authenticatorData"] = forged["authenticatorData"].clone();
        a["clientDataJSON"] = forged["clientDataJSON"].clone();
        assert_refused(&t.post("/api/action/finish", a), StatusCode::FORBIDDEN, "signature");
        assert!(t.ledger().take_operator_messages("run_c").unwrap().is_empty());
        // An unknown action.
        assert_refused(&t.begin(json!({ "action": "reboot" })), StatusCode::BAD_REQUEST, "action must be");
    }

    #[test]
    fn replayed_stale_mismatched_or_other_session_assertions_are_refused() {
        let mut t = setup("replay");
        t.running("run_d", "lead");
        // Replay: a finished action's assertion can't be used again.
        let b = t.begin(json!({ "action": "say", "run": "run_d", "text": "one" }));
        let ch = b.body["publicKey"]["challenge"].as_str().unwrap().to_string();
        let a = t.sign(&ch);
        assert_eq!(t.post("/api/action/finish", a.clone()).status, StatusCode::OK);
        assert_refused(&t.post("/api/action/finish", a), StatusCode::FORBIDDEN, "unknown, used or expired");
        // Mismatched parameters: an assertion over one action's challenge, presented for another's.
        let small = t.begin(json!({ "action": "say", "run": "run_d", "text": "harmless" }));
        let big = t.begin(json!({ "action": "revoke", "run": "run_d" }));
        let small_ch = small.body["publicKey"]["challenge"].as_str().unwrap().to_string();
        let big_ch = big.body["publicKey"]["challenge"].as_str().unwrap().to_string();
        let mut a = t.sign(&small_ch);
        a["challenge"] = big_ch.into();
        assert_refused(&t.post("/api/action/finish", a), StatusCode::FORBIDDEN, "challenge");
        assert!(t.ledger().revoked("run_d").unwrap().is_none());
        // Stale: past its two minutes.
        let b = t.begin(json!({ "action": "say", "run": "run_d", "text": "late" }));
        let ch = b.body["publicKey"]["challenge"].as_str().unwrap().to_string();
        t.state.challenges.lock().unwrap().get_mut(&ch).unwrap().expires = Instant::now() - Duration::from_secs(1);
        let a = t.sign(&ch);
        assert_refused(&t.post("/api/action/finish", a), StatusCode::FORBIDDEN, "unknown, used or expired");
        // Another session can't finish this session's action, and a login challenge isn't an action.
        let b = t.begin(json!({ "action": "say", "run": "run_d", "text": "mine" }));
        let ch = b.body["publicKey"]["challenge"].as_str().unwrap().to_string();
        let a = t.sign(&ch);
        assert_refused(&post(&t.state, "/api/action/finish", &None, &a).unwrap(), StatusCode::FORBIDDEN, "something else");
        let login = t.post("/api/login/begin", json!({}));
        let a = t.sign(login.body["publicKey"]["challenge"].as_str().unwrap());
        assert_refused(&t.post("/api/action/finish", a), StatusCode::FORBIDDEN, "something else");
        let msgs: Vec<String> = t.ledger().take_operator_messages("run_d").unwrap().into_iter().map(|m| m.0).collect();
        assert_eq!(msgs, vec!["one"]);
    }

    #[test]
    fn prefix_asks_are_approved_as_signed_and_unverified_agents_only_denied() {
        let mut t = setup("decide");
        t.running("run_e", "lead");
        t.running("run_f", "bad-agent");
        let op = |run: &str| wicket_core::Op::egress(&TenantId::single(), &RunId(run.into()), "z", "GET", "news.example", "/items/");
        let (rid, _) = t.ledger().ask(&op("run_e"), "need the item pages", true, None).unwrap();
        let b = t.begin(json!({ "action": "decide", "id": rid, "decision": "approve", "uses": 1, "ttl_secs": 600 }));
        assert_eq!(b.body["action"]["prefix"], true, "the passkey signs that this grants a prefix");
        assert_eq!(b.body["action"]["agent"], "spiffe://wicket.local/t/lead");
        let a = t.sign(b.body["publicKey"]["challenge"].as_str().unwrap());
        let r = t.post("/api/action/finish", a);
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        assert!(r.body["ok"].as_str().unwrap().contains("every path under"));
        let mut l = t.ledger();
        assert_eq!(l.request(&rid).unwrap().status, "granted");
        let deeper = wicket_core::Op::egress(&TenantId::single(), &RunId("run_e".into()), "z", "GET", "news.example", "/items/42");
        assert!(l.consume_grant(&deeper).unwrap().is_some(), "the grant covers paths under the prefix");
        let (kind, body) = t.audit_kinds().pop().unwrap();
        assert_eq!((kind.as_str(), body["prefix"].as_bool()), ("decision", Some(true)));
        // An agent whose identity doesn't verify: approval is refused, denial works.
        let (rid2, _) = t.ledger().ask(&op("run_f"), "please", true, None).unwrap();
        assert_refused(&t.begin(json!({ "action": "decide", "id": rid2, "decision": "approve" })), StatusCode::CONFLICT, "does not verify");
        let r = t.act(json!({ "action": "decide", "id": rid2, "decision": "deny" }));
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        assert_eq!(t.ledger().request(&rid2).unwrap().status, "denied");
        // The older endpoint names still work.
        let (rid3, _) = t.ledger().ask(&op("run_e"), "again", false, None).unwrap();
        let b = t.post("/api/decide/begin", json!({ "id": rid3, "decision": "deny" }));
        let a = t.sign(b.body["publicKey"]["challenge"].as_str().unwrap());
        assert_eq!(t.post("/api/decide/finish", a).status, StatusCode::OK);
        assert_eq!(t.post("/api/decide/begin", json!([])).status, StatusCode::BAD_REQUEST);
        assert_eq!(crate::verify_signed_decisions(&t.ledger()).unwrap(), (3, 0), "re-verifies offline");
    }

    #[test]
    fn wicket_principal_is_honoured_only_when_well_formed() {
        let oc = OperatorCredential { id: "c".into(), name: "laptop".into(), x: [0; 32], y: [0; 32], sign_count: 0 };
        let p = console_principal(&oc);
        assert_eq!(crate::principal_from_env(Some(&p.to_string())), Some(p.clone()));
        assert_eq!(wicket_identity::principal_label(&p), "passkey:laptop (console, passkey (user verification))");
        for bad in ["", "not json", "[]", r#"{"type":"human"}"#, r#"{"type":"human","id":7,"via":"x"}"#] {
            assert_eq!(crate::principal_from_env(Some(bad)), None, "{bad}");
        }
        assert_eq!(crate::principal_from_env(None), None);
    }

    #[test]
    fn approval_is_refused_if_the_agent_is_revoked_between_begin_and_finish() {
        let mut t = setup("revoked-mid");
        t.running("run_g", "lead");
        let op = wicket_core::Op::egress(&TenantId::single(), &RunId("run_g".into()), "z", "GET", "a.example", "/x");
        let (rid, _) = t.ledger().ask(&op, "x", false, None).unwrap();
        let b = t.begin(json!({ "action": "decide", "id": rid, "decision": "approve" }));
        // Revoked, then re-check: our fake check reads "bad" agents as unverified, so rename it.
        let l = t.ledger();
        let mut row = l.identity("run_g").unwrap().unwrap();
        row.agent = "bad-now".into();
        l.put_identity(&row).unwrap();
        let a = t.sign(b.body["publicKey"]["challenge"].as_str().unwrap());
        assert_refused(&t.post("/api/action/finish", a), StatusCode::CONFLICT, "no longer verifies");
        assert_eq!(t.ledger().request(&rid).unwrap().status, "pending");
    }

    const MANIFEST: &str = "task: say hello\nagent:\n  name: greeter\nzone:\n  name: research\n  llm:\n    secret: mock\n";

    #[test]
    fn start_run_launches_an_allowlisted_manifest_as_the_operator() {
        let mut t = setup("start");
        std::fs::write(t.dir.join("manifests/hello.yaml"), MANIFEST).unwrap();
        let listed = list_manifests(&t.state);
        assert_eq!(listed.len(), 1);
        assert_eq!((listed[0]["name"].as_str(), listed[0]["agent"].as_str()), (Some("hello.yaml"), Some("greeter")));
        assert_eq!(dashboard(&t.state).unwrap()["manifests"][0]["name"], "hello.yaml");
        let b = t.begin(json!({ "action": "start_run", "root": "manifests", "manifest": "hello.yaml", "task": "say goodbye" }));
        assert_eq!(b.status, StatusCode::OK, "{:?}", b.body);
        let run = b.body["action"]["run"].as_str().unwrap().to_string();
        assert_eq!(b.body["action"]["principal"]["id"], "passkey:laptop");
        assert_eq!(b.body["action"]["principal"]["via"], "console");
        let a = t.sign(b.body["publicKey"]["challenge"].as_str().unwrap());
        let r = t.post("/api/action/finish", a);
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        let launched = t.launched.lock().unwrap().clone();
        assert_eq!(launched.len(), 1);
        let l = &launched[0];
        assert_eq!((l.run.as_str(), l.task.as_deref()), (run.as_str(), Some("say goodbye")));
        assert_eq!(l.manifest, t.dir.join("manifests/hello.yaml"));
        assert_eq!(l.principal, console_principal(&t.ledger().operator_credentials(&TenantId::single()).unwrap()[0]));
        assert_eq!(l.log, t.dir.join("runs").join(&run).join("console.log"));
        assert!(t.dir.join("runs").join(&run).is_dir());
        let (kind, body) = t.audit_kinds().pop().unwrap();
        assert_eq!(
            (kind.as_str(), body["manifest"].as_str(), body["by"].as_str()),
            ("run.console_start", Some("hello.yaml"), Some("passkey:laptop"))
        );
        assert_eq!(crate::verify_signed_decisions(&t.ledger()).unwrap(), (1, 0), "re-verifies offline");
        // Programs take no task override.
        std::fs::write(
            t.dir.join("manifests/prog.yaml"),
            "task: count\nprogram:\n  name: counter\n  command: [\"true\"]\nzone:\n  name: research\n",
        )
        .unwrap();
        assert_refused(
            &t.begin(json!({ "action": "start_run", "root": "manifests", "manifest": "prog.yaml", "task": "x" })),
            StatusCode::BAD_REQUEST,
            "agent manifests only",
        );
    }

    #[test]
    fn start_run_refuses_paths_outside_the_allowlist_and_changed_manifests() {
        let mut t = setup("allowlist");
        std::fs::write(t.dir.join("elsewhere/evil.yaml"), MANIFEST).unwrap();
        std::fs::write(t.dir.join("manifests/hello.yaml"), MANIFEST).unwrap();
        std::os::unix::fs::symlink(t.dir.join("elsewhere/evil.yaml"), t.dir.join("manifests/link.yaml")).unwrap();
        std::fs::create_dir_all(t.dir.join("manifests/sub.yaml")).unwrap();
        for (root, name) in [
            ("manifests", "../elsewhere/evil.yaml"),
            ("manifests", "/etc/passwd"),
            ("manifests", t.dir.join("elsewhere/evil.yaml").to_str().unwrap()),
            ("manifests", "link.yaml"),
            ("manifests", "sub.yaml"),
            ("manifests", ".hidden.yaml"),
            ("manifests", "hello.txt"),
            ("elsewhere", "evil.yaml"),
            ("/tmp", "hello.yaml"),
        ] {
            let r = t.begin(json!({ "action": "start_run", "root": root, "manifest": name }));
            assert_eq!(r.status, StatusCode::FORBIDDEN, "{root}/{name}: {:?}", r.body);
        }
        let listed: Vec<String> = list_manifests(&t.state).iter().map(|m| m["name"].as_str().unwrap().to_string()).collect();
        assert_eq!(listed, vec!["hello.yaml"], "symlinks and directories aren't offered");
        // Changed between what the operator signed and the launch.
        let b = t.begin(json!({ "action": "start_run", "root": "manifests", "manifest": "hello.yaml" }));
        std::fs::write(t.dir.join("manifests/hello.yaml"), MANIFEST.replace("say hello", "rm -rf")).unwrap();
        let a = t.sign(b.body["publicKey"]["challenge"].as_str().unwrap());
        assert_refused(&t.post("/api/action/finish", a), StatusCode::CONFLICT, "changed");
        assert!(t.launched.lock().unwrap().is_empty());
    }

    #[test]
    fn the_detached_launch_runs_wicket_run_with_the_signed_parameters_and_logs_to_the_run_dir() {
        let t = setup("launch");
        let log = t.dir.join("console.log");
        let principal = json!({ "type": "human", "id": "passkey:laptop", "via": "console" });
        let l =
            Launch { run: "run_x".into(), manifest: t.dir.join("m.yaml"), task: Some("say goodbye".into()), principal, log: log.clone() };
        // A stand-in for the wicket binary that prints its arguments and principal.
        let exe = t.dir.join("fake-wicket");
        std::fs::write(&exe, "#!/bin/sh\necho \"$@\"\necho \"$WICKET_PRINCIPAL\"\n").unwrap();
        std::fs::set_permissions(&exe, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        launch_detached(&exe, &l).unwrap();
        let want = format!("run --run-id run_x --task say goodbye {}\n{}\n", l.manifest.display(), l.principal);
        for _ in 0..100 {
            if std::fs::read_to_string(&log).unwrap_or_default() == want {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("log: {:?}", std::fs::read_to_string(&log));
    }

    #[tokio::test]
    async fn posts_without_the_csrf_header_are_refused() {
        let t = setup("csrf");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sid = t.sid.clone().unwrap();
        tokio::spawn(run_server(listener, Arc::new(t.state)));
        let send = |csrf: bool| {
            let sid = sid.clone();
            async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let body = r#"{"action":"say","run":"run_x","text":"hi"}"#;
                let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
                let h = if csrf { "x-wicket-csrf: 1\r\n" } else { "" };
                let req = format!("POST /api/action/begin HTTP/1.1\r\nhost: localhost\r\ncookie: wicket_sid={sid}\r\ncontent-type: application/json\r\n{h}content-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                s.write_all(req.as_bytes()).await.unwrap();
                let mut out = String::new();
                s.read_to_string(&mut out).await.unwrap();
                out
            }
        };
        let out = send(false).await;
        assert!(out.starts_with("HTTP/1.1 403") && out.contains("x-wicket-csrf"), "{out}");
        // With the header, the same request reaches the action (and fails on its merits: no such run).
        let out = send(true).await;
        assert!(out.starts_with("HTTP/1.1 404") && out.contains("no run run_x"), "{out}");
    }
}
