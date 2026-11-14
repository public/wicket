//! `wicket serve`: the operator console (design §14.1.3), signed in and driven with passkeys, built
//! to be reachable directly from the internet.
//!
//! Security flow:
//! 1. **Enrolment** is host-only. At start-up, *only if no operator passkey exists yet*, a one-time
//!    enrolment link is printed on the host; `wicket operator enrol-link` prints a fresh one at any
//!    time (another device, a lost passkey). Links are kept in the ledger by the hash of their token,
//!    are single-use, expire (10 minutes by default), and the session one opens can do one thing:
//!    register one passkey. It cannot view runs or decide anything. A signed-in operator session
//!    cannot enrol a passkey, so a stolen session cookie can't add one.
//! 2. **Sign-in** is a passkey assertion (user verification required; no password, no fallback),
//!    rate-limited and locked out per client address and per passkey ([`limits`]), with one uniform
//!    error and every failure and lockout audited. It gives a session (`__Host-` cookie: Secure,
//!    HttpOnly, SameSite=Strict) that ends after [`SESSION_IDLE`] without requests or [`SESSION_ABSOLUTE`]
//!    in any case, is a new one at every sign-in, and is kept in the ledger (by the hash of its token)
//!    so the host can list and revoke sessions (`wicket operator sessions`, `revoke-session`).
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
//!    `wicket audit --verify` re-verifies every console action offline. A stolen session cookie
//!    alone approves nothing.
//!
//! **Pre-auth surface.** Without a session, a client can fetch the page and its static files
//! ([`web`]), call the sign-in begin/finish endpoints, and open an enrolment link. Every other
//! request, whatever its method or path, gets the same 401 with the same body: no run names, counts,
//! passkey ids or version. Requests for another `Host` than the console's origin get it too.
//!
//! **Browser.** No inline script or style; a strict CSP, no framing, no CORS, `Referrer-Policy:
//! no-referrer`, `nosniff`, COOP; HSTS on HTTPS ([`web::secure_headers`] on every response). Every
//! POST needs the `x-wicket-csrf` header and the console's own `Origin`.
//!
//! **Transport** ([`net`], [`tls`], [`acme`]): HTTPS by wicket itself (rustls; certificates from files
//! or ACME TLS-ALPN-01), or plain HTTP on loopback, or behind a TLS-terminating proxy; bounded
//! connections, timeouts and sizes.
//!
//! **Privilege separation** (#12): nothing here needs root, and runs start only through the
//! [`Launcher`] callback, so launching can later move behind a separate process unchanged.
//!
//! The browser never sends a path. Runs start only from manifests listed in an allowlisted
//! directory (see [`manifest_roots`]), named by root and file name. `wicket approve` on the host
//! remains a break-glass path and is audited as such.

mod acme;
mod authority;
mod limits;
mod manifests;
mod net;
mod tls;
mod web;

pub use net::ServeOpts;

use crate::{data_dir, grant, ledger_path};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use limits::{Limiter, Refusal};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use wicket_auth::{b64u, decision_challenge, unb64u, Credential, RelyingParty};
use wicket_core::{Manifest, RunId, TenantId};
use wicket_store::{ConsoleSession, Ledger, OperatorCredential};

/// A signed-in session ends after this long without a request (seconds)...
pub const SESSION_IDLE: i64 = 15 * 60;
/// ...and this long after sign-in in any case.
pub const SESSION_ABSOLUTE: i64 = 8 * 3600;
/// An enrolment session lasts as long as its link would have.
const BOOTSTRAP_TTL: i64 = 600;
/// How often a session's last-seen time is written back.
const TOUCH_EVERY: i64 = 15;
/// The session cookie. `__Host-`: Secure, no Domain, Path=/, so only this exact origin sets or gets it
/// (browsers treat http://localhost as secure for this).
const COOKIE: &str = "__Host-wicket_sid";
const CHALLENGE_TTL: Duration = Duration::from_secs(120);
/// Pending passkey challenges (#122). Sign-in challenges, which anyone can ask for, have a pool of
/// their own, so a flood of them never crowds out a signed-in session's actions or enrolment; each
/// pool is bounded in all, and per client address or session.
const MAX_LOGIN_CHALLENGES: usize = 512;
const MAX_SESSION_CHALLENGES: usize = 512;
const MAX_CHALLENGES_PER_OWNER: usize = 8;
/// Sign-in challenges per address block (an IPv4 /24, an IPv6 /48): one host with a routed block
/// doesn't get a pool's worth of addresses.
const MAX_LOGIN_CHALLENGES_PER_BLOCK: usize = 32;
/// Longest follow-up or task override the console accepts (characters).
const MAX_TEXT: usize = 16 * 1024;
const MAX_REASON: usize = 500;
/// The one answer to an unauthenticated request for anything but the sign-in surface.
const DENIED: &str = r#"{"error":"sign in with your passkey"}"#;
/// The one answer to a failed sign-in, whatever failed.
const SIGN_IN_FAILED: &str = "sign-in failed";
/// Why a session that didn't come from an enrolment link can't register a passkey.
const ENROL_ON_HOST: &str = "adding a passkey needs a one-time enrolment link: run `wicket operator enrol-link` on the host";

#[derive(Clone, Debug, PartialEq)]
enum SessionKind {
    /// Opened with a host-issued enrolment link (its id); may only register a passkey.
    Bootstrap {
        link: String,
    },
    Operator {
        cred: String,
    },
}

/// A console action, as the server resolved it at `begin`. Applied only with a passkey signature
/// over its canonical JSON.
#[derive(Clone, Debug, PartialEq)]
enum Action {
    Decide {
        request: String,
        approve: bool,
        uses: Option<u32>,
        ttl_secs: u64,
        /// Grant every path under this prefix (as `wicket approve --prefix`).
        prefix: Option<String>,
        /// Usable by any run in the request's zone (as `wicket approve --zone-wide`).
        zone_wide: bool,
    },
    Say {
        run: String,
        text: String,
    },
    Revoke {
        run: String,
        reason: String,
    },
    /// Save (or restore) a manifest in the installation's manifests directory (#172).
    SaveManifest(Box<manifests::Save>),
    Start {
        root: String,
        name: String,
        path: PathBuf,
        manifest_sha256: String,
        task: Option<String>,
        run: String,
        principal: Value,
        /// An agent's image, passed to its run (a program's comes from its manifest).
        image: Option<String>,
    },
}

enum Purpose {
    Register,
    Login,
    Action { action_json: String, nonce: Vec<u8>, action: Box<Action> },
}

struct Pending {
    purpose: Purpose,
    /// The session it was issued to (its id), for enrolment and actions.
    session: Option<String>,
    /// Whose quota it counts against: the client address (sign-in) or the session.
    owner: String,
    /// The client's address block, for sign-in challenges.
    block: Option<String>,
    created: Instant,
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
    /// The image the box starts from (#171): the manifest's, as shown on the start card and signed.
    /// None for a program, whose image is its manifest's `program.image`.
    pub image: Option<String>,
}

struct State {
    rp: RelyingParty,
    tenant: TenantId,
    ledger: PathBuf,
    data: PathBuf,
    roots: Vec<(String, PathBuf)>,
    launcher: Launcher,
    identity: IdentityCheck,
    challenges: Mutex<HashMap<String, Pending>>,
    limiter: Limiter,
    limits: net::Limits,
    /// Proxies whose X-Forwarded-For is believed (only with --behind-tls-terminator).
    trusted: Vec<limits::Cidr>,
    /// The Host requests must name (the origin's authority).
    authority: String,
    hsts: bool,
    /// Requests that reached a handler needing a session (the fuzz test watches it).
    authed: AtomicU64,
    /// The vault (`manifests.rs` says whether a manifest's secrets are set: names only).
    vault_dir: PathBuf,
    /// The authority root's public key, which runs' tokens load against (`authority.rs`).
    authz_root: Option<wicket_authz::PublicKey>,
}

impl State {
    fn ledger(&self) -> Result<Ledger> {
        Ok(Ledger::open(&self.ledger)?)
    }

    fn new(
        rp: RelyingParty,
        ledger: PathBuf,
        data: PathBuf,
        roots: Vec<(String, PathBuf)>,
        launcher: Launcher,
        identity: IdentityCheck,
    ) -> State {
        let authority = rp.origin.split_once("://").map(|(_, a)| a.to_string()).unwrap_or_default();
        let hsts = rp.origin.starts_with("https://");
        State {
            rp,
            tenant: TenantId::single(),
            ledger,
            data,
            roots,
            launcher,
            identity,
            challenges: Mutex::new(HashMap::new()),
            limiter: Limiter::default(),
            limits: net::Limits::default(),
            trusted: Vec::new(),
            authority,
            hsts,
            authed: AtomicU64::new(0),
            vault_dir: wicket_proxy::vault::Vault::default_dir(),
            authz_root: crate::roots::authz_root_public().ok(),
        }
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

/// What `wicket serve` with these options would serve: origin, relying-party id, transport and
/// listening address (for `wicket doctor`).
pub fn describe(opts: &ServeOpts) -> Result<(String, String, &'static str, std::net::SocketAddr)> {
    let plan = net::plan(opts, &data_dir())?;
    let how = match (&plan.tls, plan.behind_terminator) {
        (Some(net::TlsSource::Files { .. }), _) => "HTTPS, certificate files",
        (Some(net::TlsSource::Acme(_)), _) => "HTTPS, ACME",
        (None, true) => "HTTP behind a TLS terminator",
        (None, false) => "HTTP, loopback only",
    };
    Ok((plan.origin, plan.rp_id, how, plan.addr))
}

pub async fn serve(opts: ServeOpts, bootstrap_link: bool) -> Result<()> {
    let plan = net::plan(&opts, &data_dir())?;
    let tenant = TenantId::single();
    let l = Ledger::open(&ledger_path())?;
    // The console is the control host's long-lived process: it feeds the audit sinks (#91).
    crate::audit_export::spawn_background();
    let has_passkeys = !l.operator_credentials(&tenant)?.is_empty();
    let _ = l.prune_console_sessions(wicket_store::now() - 30 * 86400);
    drop(l);
    // `wicket self update` moves the console to the new build with SIGHUP (runs it started are
    // their own processes, and stay).
    crate::update::reexec_on_hangup(crate::update::pidfile("console"), crate::update::Versions::control().root, || {});
    let exe = crate::update::self_exe()?;
    let mut state = State::new(
        RelyingParty { rp_id: plan.rp_id.clone(), origin: plan.origin.clone() },
        ledger_path(),
        data_dir(),
        manifest_roots(),
        Box::new(move |l| launch_detached(&exe, l)),
        |l, run| crate::verified_identity(l, run, None),
    );
    state.trusted = plan.trusted.clone();
    state.authority = plan.authority.clone();
    state.hsts = plan.hsts;
    state.limits.max_connections = plan.max_connections;
    let state = Arc::new(state);
    let listener = TcpListener::bind(plan.addr).await.with_context(|| format!("listening on {}", plan.addr))?;
    let resolver = Arc::new(tls::CertResolver::default());
    let acceptor = match &plan.tls {
        None => None,
        Some(net::TlsSource::Files { cert, key }) => {
            let fc = tls::FileCert { cert: cert.clone(), key: key.clone() };
            resolver.set(Arc::new(fc.load()?));
            fc.watch(resolver.clone(), Duration::from_secs(60));
            Some(tokio_rustls::TlsAcceptor::from(tls::server_config(resolver.clone(), false)?))
        }
        Some(net::TlsSource::Acme(cfg)) => {
            acme::run(cfg.clone(), resolver.clone(), acme::reqwest_http(), Duration::from_secs(12 * 3600));
            println!("ACME ({}): certificate for {} kept in {}", cfg.directory, cfg.domain, cfg.cache.display());
            Some(tokio_rustls::TlsAcceptor::from(tls::server_config(resolver.clone(), true)?))
        }
    };
    let how = match (&plan.tls, plan.behind_terminator) {
        (Some(_), _) => "HTTPS",
        (None, true) => "HTTP behind a TLS terminator",
        (None, false) => "HTTP, loopback only",
    };
    println!("wicket console on {}/  (listening on {}, {how})", plan.origin, plan.addr);
    for (name, dir) in &state.roots {
        println!("runs can be started from {name}: {}", dir.display());
    }
    if has_passkeys {
        println!("sign in with your passkey. (Lost them all? On the host: wicket operator reset)");
    } else if !bootstrap_link {
        println!("no operator passkey yet. On the host, as root: wicket operator enrol-link --origin {}", plan.origin);
    } else {
        let token = issue_enrol_link(&state.ledger()?, &state.tenant, BOOTSTRAP_TTL, "wicket serve (no passkey yet)")?;
        println!("no operator passkey yet. Enrol one within 10 minutes (single use):");
        println!("  {}/enrol?t={token}", plan.origin);
    }
    net::run(listener, acceptor, state).await
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
    if let Some(i) = &l.image {
        cmd.arg("--image").arg(i);
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
    getrandom::getrandom(&mut b).expect("the OS random source");
    b
}

fn random_hex(n: usize) -> String {
    hex::encode(random_bytes(n))
}

/// Issues a single-use enrolment link valid for `ttl_secs` and returns its token (the link is
/// `ORIGIN/enrol?t=TOKEN`). Only the token's hash is stored. Audited.
pub fn issue_enrol_link(l: &Ledger, tenant: &TenantId, ttl_secs: i64, by: &str) -> Result<String> {
    let token = random_hex(24);
    let id = session_id(&token);
    l.add_enrol_link(tenant, &id, wicket_store::now() + ttl_secs, by)?;
    l.audit(tenant, None, "operator.enrol_link_issued", &json!({ "link": &id[..16], "ttl_secs": ttl_secs, "by": by }))?;
    Ok(token)
}

fn resp(status: StatusCode, ctype: &str, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::builder().status(status).header("content-type", ctype).body(Full::new(body.into())).expect("response")
}

fn denied() -> Response<Full<Bytes>> {
    resp(StatusCode::UNAUTHORIZED, "application/json", DENIED)
}

/// A JSON answer from a POST handler (and the session cookie, for sign-in).
#[derive(Debug)]
struct Reply {
    status: StatusCode,
    body: Value,
    cookie: Option<String>,
    retry_after: Option<Duration>,
}

fn ok(body: Value) -> Reply {
    Reply { status: StatusCode::OK, body, cookie: None, retry_after: None }
}

fn err(status: StatusCode, msg: impl std::fmt::Display) -> Reply {
    Reply { status, body: json!({ "error": msg.to_string() }), cookie: None, retry_after: None }
}

fn refused(r: Refusal) -> Reply {
    Reply { retry_after: Some(r.retry_after()), ..err(StatusCode::TOO_MANY_REQUESTS, "too many attempts; try again later") }
}

fn to_response(r: Reply) -> Response<Full<Bytes>> {
    let mut out = resp(r.status, "application/json", r.body.to_string());
    if let Some(c) = r.cookie {
        out.headers_mut().insert("set-cookie", c.parse().expect("cookie header"));
    }
    if let Some(d) = r.retry_after {
        out.headers_mut().insert("retry-after", d.as_secs().max(1).into());
    }
    out
}

/// Who is asking: the session cookie's token (if any) and the client address.
struct Ctx {
    sid: Option<String>,
    client: IpAddr,
}

fn cookie_sid(h: &HeaderMap) -> Option<String> {
    h.get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|c| c.trim().strip_prefix(COOKIE).and_then(|v| v.strip_prefix('=')).map(String::from))
}

/// A session's id in the ledger: the SHA-256 of its token.
fn session_id(token: &str) -> String {
    hex::encode(sha2::Sha256::digest(token.as_bytes()))
}

/// Starts a session and returns its Set-Cookie value.
fn set_session(state: &State, kind: SessionKind, client: IpAddr) -> Result<String> {
    let token = random_hex(32);
    let now = wicket_store::now();
    let ttl = if matches!(kind, SessionKind::Bootstrap { .. }) { BOOTSTRAP_TTL } else { SESSION_ABSOLUTE };
    let (kind, credential) = match kind {
        SessionKind::Bootstrap { link } => ("bootstrap", Some(link)),
        SessionKind::Operator { cred } => ("operator", Some(cred)),
    };
    state.ledger()?.add_console_session(
        &state.tenant,
        &ConsoleSession {
            id: session_id(&token),
            kind: kind.into(),
            credential,
            client: client.to_string(),
            created_at: now,
            last_seen_at: now,
            expires_at: now + ttl,
        },
    )?;
    Ok(format!("{COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={ttl}"))
}

fn clear_cookie() -> String {
    format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")
}

/// The live session a cookie names: not revoked, not past its absolute expiry, not idle for
/// [`SESSION_IDLE`], and (operator sessions) its passkey still enrolled. Returns its id and kind.
fn session(state: &State, sid: &Option<String>) -> Option<(String, SessionKind)> {
    let token = sid.as_ref()?;
    if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let id = session_id(token);
    let now = wicket_store::now();
    let l = state.ledger().ok()?;
    let s = l.console_session(&state.tenant, &id, now).ok()??;
    if now - s.last_seen_at >= SESSION_IDLE {
        let _ = l.end_console_session(&id, "idle");
        return None;
    }
    let kind = match (s.kind.as_str(), s.credential) {
        ("bootstrap", Some(link)) => SessionKind::Bootstrap { link },
        ("operator", Some(cred)) => {
            if !l.operator_credentials(&state.tenant).ok()?.iter().any(|c| c.id == cred) {
                return None;
            }
            SessionKind::Operator { cred }
        }
        _ => return None,
    };
    if now - s.last_seen_at >= TOUCH_EVERY {
        let _ = l.touch_console_session(&id, now);
    }
    Some((id, kind))
}

/// Who asks for a challenge: a client that hasn't signed in, or a signed-in session.
enum Asker {
    Client(IpAddr),
    Session(String),
}

/// Issues a challenge; None when its pool is full. Each owner keeps at most
/// [`MAX_CHALLENGES_PER_OWNER`] (a new one replaces its oldest); a sign-in challenge also counts
/// against its client's address block, and comes from the sign-in pool, which never takes the room
/// sessions need (#122).
fn new_challenge(state: &State, challenge: Vec<u8>, purpose: Purpose, asker: Asker) -> Option<String> {
    let key = b64u(&challenge);
    let (session, owner, block) = match asker {
        Asker::Client(ip) => (None, limits::ip_key(ip), Some(limits::block_key(ip))),
        Asker::Session(sid) => (Some(sid.clone()), sid, None),
    };
    let login = block.is_some();
    let mut c = state.challenges.lock().expect("lock");
    let now = Instant::now();
    c.retain(|_, v| v.expires > now);
    let oldest = |c: &HashMap<String, Pending>, f: &dyn Fn(&Pending) -> bool| -> (usize, Option<String>) {
        let mine: Vec<(&String, Instant)> = c.iter().filter(|(_, v)| f(v)).map(|(k, v)| (k, v.created)).collect();
        (mine.len(), mine.iter().min_by_key(|m| m.1).map(|m| m.0.clone()))
    };
    if let (n, Some(k)) = oldest(&c, &|v| v.owner == owner) {
        if n >= MAX_CHALLENGES_PER_OWNER {
            c.remove(&k);
        }
    }
    if let Some(b) = &block {
        if oldest(&c, &|v| v.block.as_ref() == Some(b)).0 >= MAX_LOGIN_CHALLENGES_PER_BLOCK {
            return None;
        }
    }
    let in_pool = c.values().filter(|v| v.block.is_some() == login).count();
    if in_pool >= if login { MAX_LOGIN_CHALLENGES } else { MAX_SESSION_CHALLENGES } {
        return None;
    }
    c.insert(key.clone(), Pending { purpose, session, owner, block, created: now, expires: now + CHALLENGE_TTL });
    Some(key)
}

/// Removes and returns a pending challenge (single use).
fn take_challenge(state: &State, key: &str) -> Option<Pending> {
    let p = state.challenges.lock().expect("lock").remove(key)?;
    (p.expires > Instant::now()).then_some(p)
}

fn creds(state: &State) -> Result<Vec<OperatorCredential>> {
    Ok(state.ledger()?.operator_credentials(&state.tenant)?)
}

/// Reads a JSON body within the size limit and the body timeout.
async fn json_body<B>(req: Request<B>, limits: &net::Limits) -> Result<Value, Reply>
where
    B: hyper::body::Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let declared = req.headers().get("content-length").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > limits.max_body as u64) {
        return Err(err(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"));
    }
    let read = Limited::new(req.into_body(), limits.max_body).collect();
    let b = match tokio::time::timeout(limits.body_timeout, read).await {
        Err(_) => return Err(err(StatusCode::REQUEST_TIMEOUT, "request body too slow")),
        Ok(Err(e)) if e.is::<http_body_util::LengthLimitError>() => {
            return Err(err(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"))
        }
        Ok(Err(_)) => return Err(err(StatusCode::BAD_REQUEST, "bad request body")),
        Ok(Ok(b)) => b.to_bytes(),
    };
    serde_json::from_slice(&b).map_err(|_| err(StatusCode::BAD_REQUEST, "bad JSON body"))
}

/// Every POST: the custom header (no cross-site form or simple request can send it) and the
/// console's own origin (browsers send Origin on every POST).
fn post_checks(state: &State, h: &HeaderMap) -> Option<Reply> {
    if h.get("x-wicket-csrf").map(|v| v.as_bytes()) != Some(b"1") {
        return Some(err(StatusCode::FORBIDDEN, "missing x-wicket-csrf header"));
    }
    if h.get("origin").map(|v| v.as_bytes()) != Some(state.rp.origin.as_bytes()) {
        return Some(err(StatusCode::FORBIDDEN, "cross-origin request refused"));
    }
    if h.get("sec-fetch-site").is_some_and(|v| v.as_bytes() != b"same-origin") {
        return Some(err(StatusCode::FORBIDDEN, "cross-origin request refused"));
    }
    None
}

fn field_b64(v: &Value, k: &str) -> Option<Vec<u8>> {
    v.get(k).and_then(|s| s.as_str()).and_then(|s| unb64u(s).ok())
}

/// Options for an action's assertion: any of the operator's passkeys may sign.
fn assertion_options(state: &State, key: &str) -> Value {
    let allow: Vec<Value> = creds(state).unwrap_or_default().iter().map(|c| json!({ "type": "public-key", "id": c.id })).collect();
    json!({ "challenge": key, "rpId": state.rp.rp_id, "allowCredentials": allow, "userVerification": "required", "timeout": 120000 })
}

/// Every request: security headers on whatever the handlers answer.
async fn route<B>(req: Request<B>, state: &State, peer: SocketAddr) -> Response<Full<Bytes>>
where
    B: hyper::body::Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut r = dispatch(req, state, peer).await;
    web::secure_headers(r.headers_mut(), state.hsts);
    r
}

async fn dispatch<B>(req: Request<B>, state: &State, peer: SocketAddr) -> Response<Full<Bytes>>
where
    B: hyper::body::Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    // Only requests for the console's own origin (DNS rebinding, scanners by IP).
    let host = req.headers().get(http::header::HOST).and_then(|h| h.to_str().ok()).or(req.uri().authority().map(|a| a.as_str()));
    if !host.is_some_and(|h| h.eq_ignore_ascii_case(&state.authority)) {
        return denied();
    }
    let forwarded: Vec<Option<&str>> = req.headers().get_all("x-forwarded-for").iter().map(|v| v.to_str().ok()).collect();
    let ctx = Ctx { sid: cookie_sid(req.headers()), client: limits::client_ip(peer.ip(), &forwarded, &state.trusted) };
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // The pre-auth surface: the page, its static files, sign-in, the enrolment link.
    if method == Method::GET {
        if path == "/" {
            return resp(StatusCode::OK, "text/html; charset=utf-8", web::ASSETS.page.clone());
        }
        if let Some(a) = web::ASSETS.files.get(&path) {
            let mut r = resp(StatusCode::OK, a.ctype, a.body.clone());
            let cache = if a.immutable { "public, max-age=31536000, immutable" } else { "public, max-age=3600" };
            r.headers_mut().insert("cache-control", http::HeaderValue::from_static(cache));
            return r;
        }
        if path == "/enrol" {
            return enrol(state, req.uri().query().unwrap_or(""), &ctx);
        }
    }
    let sign_in = method == Method::POST && matches!(path.as_str(), "/api/login/begin" | "/api/login/finish");
    let sess = if sign_in { None } else { session(state, &ctx.sid) };
    if !sign_in && sess.is_none() {
        return denied();
    }
    if !sign_in {
        state.authed.fetch_add(1, Ordering::Relaxed);
    }

    if method == Method::GET {
        return match path.as_str() {
            "/api/me" => match &sess {
                Some((_, SessionKind::Operator { cred })) => to_response(ok(json!({ "who": { "state": "operator", "credential": cred } }))),
                _ => to_response(ok(json!({ "who": { "state": "bootstrap" } }))),
            },
            "/api/state" => match &sess {
                Some((_, SessionKind::Operator { .. })) => match dashboard(state) {
                    Ok(v) => to_response(ok(v)),
                    Err(e) => to_response(err(StatusCode::INTERNAL_SERVER_ERROR, e)),
                },
                _ => denied(),
            },
            // A manifest, viewed (#172): an operator's session only.
            p if p.starts_with("/api/manifests/") => match &sess {
                Some((_, SessionKind::Operator { .. })) => match p["/api/manifests/".len()..].split_once('/') {
                    Some((root, name)) => match manifests::view(state, root, name) {
                        Ok(v) => to_response(ok(v)),
                        Err(e) => to_response(err(StatusCode::NOT_FOUND, format!("{e:#}"))),
                    },
                    None => resp(StatusCode::NOT_FOUND, "text/plain", "not found"),
                },
                _ => denied(),
            },
            // Read-only views of authority (#173): an operator's session only.
            p => match (authority::get(state, p), &sess) {
                (Some(r), Some((_, SessionKind::Operator { .. }))) => match r {
                    Ok(v) => to_response(ok(v)),
                    Err(e) => to_response(err(StatusCode::NOT_FOUND, e)),
                },
                (Some(_), _) => denied(),
                (None, _) => resp(StatusCode::NOT_FOUND, "text/plain", "not found"),
            },
        };
    }
    if method != Method::POST {
        return resp(StatusCode::METHOD_NOT_ALLOWED, "text/plain", "method not allowed");
    }
    if let Some(r) = post_checks(state, req.headers()) {
        return to_response(r);
    }
    let body = match json_body(req, &state.limits).await {
        Ok(b) => b,
        Err(r) => return to_response(r),
    };
    match post(state, &path, &ctx, &body) {
        Some(r) => to_response(r),
        None => resp(StatusCode::NOT_FOUND, "text/plain", "not found"),
    }
}

/// The one-time enrolment link. Any failure (no enrolment open, wrong or used token, throttled)
/// looks exactly like any other unauthenticated request.
fn enrol(state: &State, query: &str, ctx: &Ctx) -> Response<Full<Bytes>> {
    let now = Instant::now();
    if state.limiter.attempt(ctx.client, now).is_err() {
        return denied();
    }
    let t = query.split('&').find_map(|kv| kv.strip_prefix("t=")).unwrap_or("");
    // Looked up by the token's hash, and used atomically: a link works once, before it expires.
    let link = session_id(t);
    let used = !t.is_empty()
        && state
            .ledger()
            .and_then(|l| Ok(l.use_enrol_link(&state.tenant, &link, wicket_store::now(), &ctx.client.to_string())?))
            .unwrap_or(false);
    if !used {
        audit_failure(state, ctx, None, "enrolment link invalid, used or expired", "operator.enrol_failed");
        return denied();
    }
    let Ok(cookie) = set_session(state, SessionKind::Bootstrap { link: link.clone() }, ctx.client) else { return denied() };
    if let Ok(l) = state.ledger() {
        let _ = l.audit(&state.tenant, None, "operator.enrol_link_used", &json!({ "link": &link[..16], "client": ctx.client.to_string() }));
    }
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header("location", "/")
        .header("set-cookie", cookie)
        .body(Full::new(Bytes::new()))
        .expect("response")
}

/// Records a failed sign-in or enrolment (and any lockout it starts) in the audit log.
fn audit_failure(state: &State, ctx: &Ctx, cred: Option<&str>, reason: &str, kind: &str) {
    let cred: Option<String> = cred.map(|c| c.chars().take(200).collect());
    let locked = cred.as_deref().is_some_and(|c| state.limiter.credential_locked(c, Instant::now()).is_some());
    // A credential already locked out isn't counted again (that would only lengthen the operator's
    // own lockout); the client address is.
    let lockouts = state.limiter.fail(ctx.client, if locked { None } else { cred.as_deref() }, Instant::now());
    let Ok(l) = state.ledger() else { return };
    let _ = l.audit(&state.tenant, None, kind, &json!({ "client": ctx.client.to_string(), "credential": cred, "reason": reason }));
    for lo in lockouts {
        tracing::warn!("console sign-in lockout: {} {} for {}s", lo.scope, lo.key, lo.duration.as_secs());
        let _ = l.audit(
            &state.tenant,
            None,
            "operator.lockout",
            &json!({ "scope": lo.scope, "key": lo.key, "seconds": lo.duration.as_secs(), "client": ctx.client.to_string() }),
        );
    }
}

/// Every POST endpoint, after the CSRF/origin checks and body parsing. None: no such endpoint.
fn post(state: &State, path: &str, ctx: &Ctx, body: &Value) -> Option<Reply> {
    let sess = match path {
        "/api/login/begin" | "/api/login/finish" => None,
        _ => session(state, &ctx.sid),
    };
    Some(match path {
        "/api/register/begin" => register_begin(state, &sess),
        "/api/register/finish" => register_finish(state, &sess, body),
        "/api/login/begin" => login_begin(state, ctx),
        "/api/login/finish" => login_finish(state, ctx, body),
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
        // Validates edited manifest YAML and diffs its authority (#172): read-only, so unsigned.
        "/api/manifests/check" => match &sess {
            Some((_, SessionKind::Operator { .. })) => match manifests::check(state, body) {
                Ok(v) => ok(v),
                Err(e) => err(StatusCode::BAD_REQUEST, format!("{e:#}")),
            },
            _ => err(StatusCode::UNAUTHORIZED, "sign in with your passkey"),
        },
        "/api/logout" => {
            if let (Some((id, _)), Ok(l)) = (&sess, state.ledger()) {
                let _ = l.end_console_session(id, "sign-out");
            }
            Reply { cookie: Some(clear_cookie()), ..ok(json!({ "ok": "signed out" })) }
        }
        _ => return None,
    })
}

fn register_begin(state: &State, sess: &Option<(String, SessionKind)>) -> Reply {
    // Only a session opened with a host-issued enrolment link may enrol, never a signed-in operator
    // session: a stolen cookie must not be able to add a passkey.
    let Some((sid, SessionKind::Bootstrap { .. })) = sess else { return err(StatusCode::FORBIDDEN, ENROL_ON_HOST) };
    let challenge = random_bytes(32);
    let Some(key) = new_challenge(state, challenge, Purpose::Register, Asker::Session(sid.clone())) else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "too many passkey ceremonies in progress; try again shortly");
    };
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
    let Some((sid, SessionKind::Bootstrap { link })) = sess else { return err(StatusCode::FORBIDDEN, ENROL_ON_HOST) };
    let (Some(ch), Some(cdj), Some(att)) =
        (body.get("challenge").and_then(|c| c.as_str()), field_b64(body, "clientDataJSON"), field_b64(body, "attestationObject"))
    else {
        return err(StatusCode::BAD_REQUEST, "challenge, clientDataJSON and attestationObject are required");
    };
    let Some(p) = take_challenge(state, ch) else { return err(StatusCode::FORBIDDEN, "unknown or expired challenge") };
    if !matches!(p.purpose, Purpose::Register) || p.session.as_ref() != Some(sid) {
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
            let client = l.console_session(&state.tenant, sid, wicket_store::now()).ok().flatten().map(|s| s.client);
            let _ = l.audit(
                &state.tenant,
                None,
                "operator.passkey_added",
                &json!({ "credential": oc.id, "name": oc.name, "via": "enrolment link", "link": &link[..16.min(link.len())], "client": client }),
            );
            // The enrolment session has done its one job: end it, so the next step is a real sign-in.
            let _ = l.end_console_session(sid, "enrolled");
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

/// Sign-in, step 1: a challenge. The same answer whether or not any passkey is enrolled, and no
/// `allowCredentials` (passkeys are discoverable), so it discloses no credential ids.
fn login_begin(state: &State, ctx: &Ctx) -> Reply {
    if let Err(r) = state.limiter.attempt(ctx.client, Instant::now()) {
        return refused(r);
    }
    let Some(key) = new_challenge(state, random_bytes(32), Purpose::Login, Asker::Client(ctx.client)) else {
        return refused(Refusal::Throttled(Duration::from_secs(5)));
    };
    ok(
        json!({ "publicKey": { "challenge": key, "rpId": state.rp.rp_id, "allowCredentials": [], "userVerification": "required", "timeout": 120000 } }),
    )
}

/// Sign-in, step 2: the assertion. Any failure gets the same answer; the reason goes to the audit log.
fn login_finish(state: &State, ctx: &Ctx, body: &Value) -> Reply {
    let now = Instant::now();
    if let Err(r) = state.limiter.attempt(ctx.client, now) {
        return refused(r);
    }
    let cred = body.get("id").and_then(|s| s.as_str());
    let fail = |reason: &str| {
        audit_failure(state, ctx, cred, reason, "operator.login_failed");
        err(StatusCode::UNAUTHORIZED, SIGN_IN_FAILED)
    };
    let Some(ch) = body.get("challenge").and_then(|c| c.as_str()) else { return fail("no challenge") };
    let Some(p) = take_challenge(state, ch) else { return fail("unknown, used or expired challenge") };
    if !matches!(p.purpose, Purpose::Login) {
        return fail("challenge was issued for something else");
    }
    if cred.is_some_and(|c| state.limiter.credential_locked(c, now).is_some()) {
        return fail("passkey locked out");
    }
    let a = match verify_assertion(state, ch, body) {
        Ok(a) => a,
        Err(r) => return fail(r.body["error"].as_str().unwrap_or("assertion refused")),
    };
    state.limiter.succeed(ctx.client, &a.oc.id, now);
    let Ok(l) = state.ledger() else { return err(StatusCode::INTERNAL_SERVER_ERROR, "ledger unavailable") };
    // A new session at every sign-in; whatever session the browser had ends.
    if let Some(old) = &ctx.sid {
        let _ = l.end_console_session(&session_id(old), "replaced at sign-in");
    }
    let cookie = match set_session(state, SessionKind::Operator { cred: a.oc.id.clone() }, ctx.client) {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let _ = l.audit(
        &state.tenant,
        None,
        "operator.signed_in",
        &json!({ "credential": a.oc.id, "name": a.oc.name, "client": ctx.client.to_string() }),
    );
    Reply { cookie: Some(cookie), ..ok(json!({ "ok": format!("signed in with {}", a.oc.name) })) }
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
/// A manifest's file name: letters, digits, '.', '_', '-', ending .yaml or .yml, no `..`.
fn check_manifest_name(name: &str) -> Result<()> {
    let ok_name = name.len() <= 128
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && !name.contains("..")
        && (name.ends_with(".yaml") || name.ends_with(".yml"));
    if !ok_name {
        bail!("{name:?} is not a manifest file name (letters, digits, '.', '_', '-'; ending .yaml or .yml)");
    }
    Ok(())
}

fn resolve_manifest(state: &State, root: &str, name: &str) -> Result<(PathBuf, Vec<u8>)> {
    check_manifest_name(name)?;
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
                    // The image its box starts from (#171), or why it can't start.
                    "image": m.as_ref().and_then(|m| crate::run::manifest_image(m).ok()),
                    "image_error": m.as_ref().and_then(|m| crate::run::manifest_image(m).err().map(|e| format!("{e:#}"))),
                    // The zone view (#62): which hosts the egress proxy inspects, which it splices.
                    "hosts": m.as_ref().map(|m| wicket_core::splice::view(&m.zone).into_iter().map(|(h, i)| match i {
                        wicket_core::splice::Inspection::Spliced { rule } => json!({ "host": h, "mode": "spliced", "rule": rule }),
                        wicket_core::splice::Inspection::Inspected(why) => json!({ "host": h, "mode": "inspected", "why": why }),
                    }).collect::<Vec<_>>()),
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
            let prefix = match body.get("prefix") {
                None | Some(Value::Null) => None,
                Some(Value::String(p)) if approve => {
                    let p = wicket_core::canonical_path(p).map_err(|e| bad(&format!("prefix: {e}")))?.to_string();
                    crate::grant::check_prefix(&req, &p).map_err(|e| bad(&e))?;
                    Some(p)
                }
                Some(Value::String(_)) => None,
                Some(_) => return Err(bad("prefix must be a path")),
            };
            let zone_wide = approve && body.get("zone_wide").and_then(|z| z.as_bool()).unwrap_or(false);
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
                // A prefix ask (request_access with scope prefix) is granted as every path under `path`,
                // or under `path_prefix` if the human names one; `scope` says which runs may use it.
                "prefix": req.scope_prefix || prefix.is_some(),
                "path_prefix": prefix, "scope": if zone_wide { "zone" } else { "run" },
                "decision": if approve { "approve" } else { "deny" },
                "uses": uses, "ttl_secs": if approve { Some(ttl_secs) } else { None },
                // Who the human was told this is for; the passkey signs it with the decision: the
                // agent's verified identity (bound by its document's digest) and, inside its box,
                // which subagent reportedly asked.
                "agent": identity.get("id"), "identity_sha256": identity.get("identity_sha256"),
                "identity_verified": identity.get("verified"),
                "requested_by": req.attribution.iter().flat_map(wicket_proxy::attributed_agents).collect::<Vec<_>>(),
            });
            Ok((Action::Decide { request: req.id, approve, uses, ttl_secs, prefix, zone_wide }, v))
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
            // The image is the manifest's (#171), checked against zone.images before anything is signed.
            let image = crate::run::manifest_image(&m).map_err(|e| err(StatusCode::FORBIDDEN, format!("{root}/{name}: {e:#}")))?;
            let manifest_sha256 = hex::encode(sha2::Sha256::digest(&bytes));
            let run = RunId::new().0;
            let principal = console_principal(oc);
            let v = json!({
                "v": 1, "action": "start_run", "tenant": state.tenant.0, "root": root, "manifest": name,
                "manifest_sha256": manifest_sha256, "task": task, "run": run,
                "agent": m.agent.as_ref().map(|a| a.name.clone()), "program": m.program.as_ref().map(|p| p.name.clone()),
                "zone": m.zone.name, "image": image, "principal": principal,
            });
            let image = m.agent.is_some().then_some(image);
            Ok((Action::Start { root: root.into(), name: name.into(), path, manifest_sha256, task, run, principal, image }, v))
        }
        Some(kind @ ("save_manifest" | "restore_manifest")) => {
            let (save, v) =
                manifests::prepare(state, kind, body, &state.tenant.0).map_err(|e| err(StatusCode::BAD_REQUEST, format!("{e:#}")))?;
            Ok((Action::SaveManifest(Box::new(save)), v))
        }
        _ => Err(bad("action must be decide, say, revoke, start_run, save_manifest or restore_manifest")),
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
    let Some(key) =
        new_challenge(state, challenge, Purpose::Action { action_json, nonce, action: Box::new(action) }, Asker::Session(sid.clone()))
    else {
        return err(StatusCode::SERVICE_UNAVAILABLE, "too many passkey ceremonies in progress; try again shortly");
    };
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
        Action::Decide { request, approve: true, uses, ttl_secs, prefix, zone_wide } => {
            // The agent may have been revoked since the operator was shown it.
            let req = l.request(request)?;
            if !identity_approvable(&(state.identity)(&l, &req.run)) {
                bail!("{request}: the requesting agent's identity no longer verifies; it can be denied, not approved");
            }
            let t = grant::Terms { uses: *uses, ttl: Duration::from_secs(*ttl_secs), prefix: prefix.clone(), zone_wide: *zone_wide };
            let grant::Decided::Approved { grant, lease } =
                grant::decide(&mut l, &grant::Granter::Human(by), request, &grant::Verdict::Approve(t), json!({ "action": "decide", "signed": signed }))?
            else {
                unreachable!("an approval approves")
            };
            let under = prefix.as_deref().map(wicket_core::prefix_dir).or(req.scope_prefix.then(|| req.path.clone()));
            let scope = under.map(|p| format!(" for every path under {}{p}", req.host)).unwrap_or_default();
            let zone = if *zone_wide { format!(", for any run in zone {}", req.zone) } else { String::new() };
            let lease = lease.map(|x| format!("; lease {x} is provisioned by the next reconcile pass")).unwrap_or_default();
            Ok(format!("approved {request} → {grant}{scope}{zone}{lease} (signed with {})", oc.name))
        }
        Action::Decide { request, approve: false, .. } => {
            let lease = match grant::decide(&mut l, &grant::Granter::Human(by), request, &grant::Verdict::Deny, json!({ "action": "decide", "signed": signed }))? {
                grant::Decided::Denied { lease } => lease,
                grant::Decided::Approved { .. } => unreachable!("a denial denies"),
            };
            let lease = lease.map(|x| format!("; lease {x}'s reservation is released")).unwrap_or_default();
            Ok(format!("denied {request}{lease} (signed with {})", oc.name))
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
        Action::SaveManifest(save) => {
            manifests::apply(state, save)?;
            let signed_action: Value =
                signed.get("action_json").and_then(|j| j.as_str()).and_then(|j| serde_json::from_str(j).ok()).unwrap_or_default();
            l.audit(
                t,
                None,
                "manifest.saved",
                &json!({ "action": signed_action["action"], "root": manifests::WRITABLE_ROOT, "name": save.name, "sha256": save.sha256,
                         "previous_sha256": save.previous_sha256, "restored_from": signed_action["restored_from"],
                         "widens": signed_action["widens"], "widening": signed_action["widening"], "changes": signed_action["changes"],
                         "by": by, "signed": signed }),
            )?;
            Ok(format!(
                "saved {}/{} (sha256 {}…); the previous version is kept in its history",
                manifests::WRITABLE_ROOT,
                save.name,
                &save.sha256[..12]
            ))
        }
        Action::Start { root, name, path, manifest_sha256, task, run, principal, image } => {
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
                         "task": task, "image": image, "principal": principal, "by": by, "signed": signed }),
            )?;
            drop(l);
            (state.launcher)(&Launch {
                run: run.clone(),
                manifest: path.clone(),
                task: task.clone(),
                principal: principal.clone(),
                log: log.clone(),
                image: image.clone(),
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
            // A remote session's address (#169), as its run recorded it.
            if let Some(u) = l
                .audit_latest(&id, "run.remote_session")
                .ok()
                .flatten()
                .and_then(|b| serde_json::from_str::<Value>(&b).ok())
                .and_then(|b| b["url"].as_str().filter(|u| u.starts_with("https://")).map(String::from))
            {
                v["remote_url"] = u.into();
            }
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
    const LOCAL: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    fn anon() -> Ctx {
        Ctx { sid: None, client: LOCAL }
    }

    /// The token in a Set-Cookie value.
    fn token_of(cookie: &str) -> String {
        cookie.strip_prefix("__Host-wicket_sid=").unwrap().split(';').next().unwrap().to_string()
    }

    struct T {
        state: State,
        key: SigningKey,
        cred: String,
        sid: Option<String>,
        count: u32,
        launched: Arc<Mutex<Vec<Launch>>>,
        dir: PathBuf,
        _tmp: TmpDir,
    }

    /// A test's temporary directory, removed when the test is done with it.
    pub(super) struct TmpDir(pub(super) PathBuf);

    impl TmpDir {
        pub(super) fn new(name: &str) -> TmpDir {
            let d = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            TmpDir(d)
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
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
        let tmp = TmpDir::new(&format!("wicket-serve-{tag}"));
        let dir = tmp.0.clone();
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
        let state = State::new(
            RelyingParty { rp_id: "localhost".into(), origin: ORIGIN.into() },
            ledger,
            dir.clone(),
            vec![("manifests".into(), dir.join("manifests"))],
            Box::new(move |l| {
                rec.lock().unwrap().push(l.clone());
                Ok(())
            }),
            fake_identity,
        );
        let cookie = set_session(&state, SessionKind::Operator { cred: cred.clone() }, LOCAL).unwrap();
        let sid = token_of(&cookie);
        T { state, key, cred, sid: Some(sid), count: 0, launched, dir, _tmp: tmp }
    }

    impl T {
        fn ledger(&self) -> Ledger {
            self.state.ledger().unwrap()
        }

        fn post(&self, path: &str, body: Value) -> Reply {
            post(&self.state, path, &self.ctx(), &body).expect("endpoint")
        }

        fn ctx(&self) -> Ctx {
            Ctx { sid: self.sid.clone(), client: LOCAL }
        }

        fn begin(&self, body: Value) -> Reply {
            self.post("/api/action/begin", body)
        }

        /// What a browser returns from navigator.credentials.get for `challenge` (base64url).
        fn sign(&mut self, challenge: &str) -> Value {
            self.sign_flags(challenge, 0x01 | 0x04) // user present, user verified
        }

        /// [`T::sign`] with the given authenticator flags.
        fn sign_flags(&mut self, challenge: &str, flags: u8) -> Value {
            self.count += 1;
            let cdj =
                json!({ "type": "webauthn.get", "challenge": challenge, "origin": ORIGIN, "crossOrigin": false }).to_string().into_bytes();
            let mut ad = sha2::Sha256::digest(b"localhost").to_vec();
            ad.push(flags);
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

    mod authority;
    mod http;
    mod https;
    mod manifests;

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
        assert_refused(&post(&t.state, "/api/action/begin", &anon(), &say).unwrap(), StatusCode::UNAUTHORIZED, "sign in");
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
        assert_refused(&post(&t.state, "/api/action/finish", &anon(), &a).unwrap(), StatusCode::FORBIDDEN, "something else");
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
        assert_eq!((kind.as_str(), body["scope_prefix"].as_bool()), ("decision", Some(true)));
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

    /// #254: the console decides through `cmd/approve`'s functions, as `wicket approve` and `deny`
    /// do: a prefix the human names, zone-wide scope, and a capacity ask's lease.
    #[test]
    fn console_decisions_take_a_prefix_zone_wide_scope_and_leases() {
        let mut t = setup("decide-scope");
        t.running("run_e", "lead");
        t.running("run_g", "other");
        let op = |run: &str, path: &str| wicket_core::Op::egress(&TenantId::single(), &RunId(run.into()), "z", "GET", "news.example", path);
        // A prefix ask, narrowed by the human to a prefix within it.
        let (rid, _) = t.ledger().ask(&op("run_e", "/items/"), "item pages", true, None).unwrap();
        let wide = json!({ "action": "decide", "id": rid, "decision": "approve", "prefix": "/elsewhere/" });
        assert_refused(&t.begin(wide), StatusCode::BAD_REQUEST, "doesn't cover");
        let b = t.begin(json!({ "action": "decide", "id": rid, "decision": "approve", "uses": 5, "prefix": "/items/a/" }));
        assert_eq!((b.body["action"]["path_prefix"].as_str(), b.body["action"]["prefix"].as_bool()), (Some("/items/a/"), Some(true)));
        let a = t.sign(b.body["publicKey"]["challenge"].as_str().unwrap());
        let r = t.post("/api/action/finish", a);
        assert!(r.body["ok"].as_str().unwrap().contains("every path under news.example/items/a/"), "{:?}", r.body);
        let mut l = t.ledger();
        assert!(l.consume_grant(&op("run_e", "/items/a/1")).unwrap().is_some());
        assert!(l.consume_grant(&op("run_e", "/items/b/1")).unwrap().is_none(), "narrowed to what the human named");
        // Zone-wide: another run in the zone may use it too.
        let (rid, _) = t.ledger().ask(&op("run_e", "/feed"), "the feed", false, None).unwrap();
        let b = t.begin(json!({ "action": "decide", "id": rid, "decision": "approve", "unlimited": true, "zone_wide": true }));
        assert_eq!(b.body["action"]["scope"], "zone");
        let a = t.sign(b.body["publicKey"]["challenge"].as_str().unwrap());
        assert!(t.post("/api/action/finish", a).body["ok"].as_str().unwrap().contains("any run in zone z"));
        assert!(t.ledger().consume_grant(&op("run_g", "/feed")).unwrap().is_some(), "zone-wide");
        let (_, rec) = t.audit_kinds().pop().unwrap();
        assert_eq!((rec["scope"].as_str(), rec["action"].as_str()), (Some("zone"), Some("decide")));
        // A capacity ask: denying it releases its lease's reservation at once.
        let mut l = t.ledger();
        let row = wicket_store::LeaseRow {
            id: "l-c".into(),
            tenant: TenantId::single().0,
            run: "run_e".into(),
            request_id: None,
            provider: "static".into(),
            spec: json!({}),
            hourly_cap: 0,
            reserved: 0,
            duration_secs: 1800,
            created_at: 0,
            not_after: None,
            status: "pending".into(),
            node_id: None,
            node_name: None,
            ssh_target: None,
            host_key: None,
            billed: None,
            ended_at: None,
            detail: None,
        };
        l.create_lease(&row, wicket_store::LeaseBudget { max_hourly: 0, max_total: 0 }).unwrap().unwrap();
        let cap = wicket_core::Op::egress(&TenantId::single(), &RunId("run_e".into()), "z", "CAPACITY", "wicket.internal", "/capacity/l-c");
        let (rid, _) = l.pending_for(&cap, "a node", None).unwrap();
        l.set_lease_request("l-c", &rid).unwrap();
        let r = t.act(json!({ "action": "decide", "id": rid, "decision": "deny" }));
        assert!(r.body["ok"].as_str().unwrap().contains("lease l-c's reservation is released"), "{:?}", r.body);
        assert_eq!(t.ledger().lease("l-c").unwrap().unwrap().status, "denied");
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

    /// #171: a console start uses the manifest's agent.image: listed, signed, audited and passed to
    /// the run; one outside zone.images is refused before anything is signed.
    #[test]
    fn start_run_uses_the_manifests_agent_image() {
        let mut t = setup("image");
        let rust = MANIFEST
            .replace("  name: greeter\n", "  name: greeter\n  image: img:rust\n")
            .replace("    secret: mock\n", "    secret: mock\n  images: [img:rust]\n");
        std::fs::write(t.dir.join("manifests/rust.yaml"), &rust).unwrap();
        std::fs::write(t.dir.join("manifests/plain.yaml"), MANIFEST).unwrap();
        std::fs::write(t.dir.join("manifests/stray.yaml"), rust.replace("images: [img:rust]", "images: []")).unwrap();
        let listed = list_manifests(&t.state);
        let by = |n: &str| listed.iter().find(|m| m["name"] == n).unwrap().clone();
        assert_eq!(by("rust.yaml")["image"], "img:rust");
        assert_eq!(by("plain.yaml")["image"].as_str(), Some(crate::image::effective(crate::image::DEFAULT).as_str()));
        assert!(by("stray.yaml")["image"].is_null() && by("stray.yaml")["image_error"].as_str().unwrap().contains("zone.images"));

        let b = t.begin(json!({ "action": "start_run", "root": "manifests", "manifest": "rust.yaml" }));
        assert_eq!(b.status, StatusCode::OK, "{:?}", b.body);
        assert_eq!(b.body["action"]["image"], "img:rust", "the start card shows (and the passkey signs) the image");
        let a = t.sign(b.body["publicKey"]["challenge"].as_str().unwrap());
        assert_eq!(t.post("/api/action/finish", a).status, StatusCode::OK);
        assert_eq!(t.launched.lock().unwrap()[0].image.as_deref(), Some("img:rust"));
        let (kind, body) = t.audit_kinds().pop().unwrap();
        assert_eq!((kind.as_str(), body["image"].as_str()), ("run.console_start", Some("img:rust")));

        assert_refused(
            &t.begin(json!({ "action": "start_run", "root": "manifests", "manifest": "stray.yaml" })),
            StatusCode::FORBIDDEN,
            "zone.images",
        );
        assert_eq!(t.launched.lock().unwrap().len(), 1, "nothing more was started");
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
        let l = Launch {
            run: "run_x".into(),
            manifest: t.dir.join("m.yaml"),
            task: Some("say goodbye".into()),
            principal,
            log: log.clone(),
            image: Some("img:rust".into()),
        };
        // A stand-in for the wicket binary that prints its arguments and principal.
        let exe = t.dir.join("fake-wicket");
        std::fs::write(&exe, "#!/bin/sh\necho \"$@\"\necho \"$WICKET_PRINCIPAL\"\n").unwrap();
        std::fs::set_permissions(&exe, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        launch_detached(&exe, &l).unwrap();
        let want = format!("run --run-id run_x --task say goodbye --image img:rust {}\n{}\n", l.manifest.display(), l.principal);
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
        tokio::spawn(net::run(listener, None, Arc::new(t.state)));
        let send = |csrf: bool| {
            let sid = sid.clone();
            async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let body = r#"{"action":"say","run":"run_x","text":"hi"}"#;
                let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
                let h = if csrf { "x-wicket-csrf: 1\r\n" } else { "" };
                let req = format!("POST /api/action/begin HTTP/1.1\r\nhost: localhost:8787\r\norigin: http://localhost:8787\r\ncookie: __Host-wicket_sid={sid}\r\ncontent-type: application/json\r\n{h}content-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
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
