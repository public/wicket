//! The secret helper (#350): `wicket secret serve`, run as the owner of a file a secret is linked
//! to (a harness's login), serves that secret's current value to wicketd over a unix socket, so the
//! wicket user needs no ACL on the file.
//!
//! - **The helper decides what it serves.** It is started with each secret's name, file and JSON
//!   pointer (and expiry pointer). wicketd asks by name only and gets back the pointed-to value and
//!   its expiry, nothing else from the file: a Claude login's refresh token never leaves its owner.
//! - **Both ends check the other by the kernel's word (`SO_PEERCRED`).** The helper answers only the
//!   uids it serves (wicketd's user); the vault takes an answer only from the uid the link names, so
//!   a process that took the socket's name first can't hand wicketd a value of its own.
//! - **The socket** is in the abstract namespace by default (`@wicket-secret.<owner uid>`): no
//!   directory both users must reach, and nothing for a refresh to break. Boxes have their own
//!   network namespace, so none can reach it. A path works too, for hosts that prefer one.
//!
//! The protocol is one JSON line each way: `{"secret": NAME}`, then `{"value": V, "expires_at": MS}`
//! or `{"error": WHY}`.

use anyhow::{bail, Context, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

/// How long either end waits for the other.
const TIMEOUT: Duration = Duration::from_secs(2);
/// The longest request line the helper reads.
const MAX_REQUEST: u64 = 1024;
/// The longest answer the vault reads.
const MAX_ANSWER: u64 = 1 << 20;

/// Where a linked secret's helper listens, and whose it must be: kept in the link (`<name>.ref`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HelperRef {
    /// The uid the helper must run as (the file's owner): an answer from any other is refused.
    pub uid: u32,
    /// `@name` for the abstract namespace, else a path.
    pub socket: String,
}

/// The helper's socket for `uid` when none is named: `@wicket-secret.<uid>`.
pub fn default_socket(uid: u32) -> String {
    format!("@wicket-secret.{uid}")
}

/// A value the helper served, and when it expires (Unix ms) if its file says.
#[derive(Clone, PartialEq, Eq)]
pub struct Answer {
    pub value: String,
    pub expires_at: Option<i64>,
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Answer").field("value", &"<redacted>").field("expires_at", &self.expires_at).finish()
    }
}

impl HelperRef {
    /// Asks the helper for `name`'s current value. Refused unless the helper runs as `self.uid`, or
    /// if the value it gives has expired.
    pub fn fetch(&self, name: &str) -> Result<Answer> {
        let s = connect(&self.socket).with_context(|| {
            format!(
                "the secret helper for secret {name} isn't reachable at {} (it runs as uid {}: `wicket secret serve`, e.g. \
                 deploy/systemd-user/wicket-secret-helper.service)",
                self.socket, self.uid
            )
        })?;
        let theirs = peer_uid(&s)?;
        if theirs != self.uid {
            bail!(
                "the secret helper socket {} is held by uid {theirs}, not uid {} whose helper secret {name} is linked to: refused",
                self.socket,
                self.uid
            );
        }
        s.set_read_timeout(Some(TIMEOUT))?;
        s.set_write_timeout(Some(TIMEOUT))?;
        let mut w = &s;
        w.write_all(format!("{}\n", serde_json::json!({ "secret": name })).as_bytes())?;
        let mut line = String::new();
        BufReader::new((&s).take(MAX_ANSWER)).read_line(&mut line).with_context(|| format!("reading the helper's answer for {name}"))?;
        let a: serde_json::Value =
            serde_json::from_str(&line).with_context(|| format!("the secret helper's answer for {name} is not JSON"))?;
        if let Some(e) = a.get("error").and_then(|e| e.as_str()) {
            bail!("the secret helper (uid {}) says: {e}", self.uid);
        }
        let value = a.get("value").and_then(|v| v.as_str()).filter(|v| !v.trim().is_empty());
        let value = value.with_context(|| format!("the secret helper gave no value for {name}"))?.to_string();
        let expires_at = a.get("expires_at").and_then(|v| v.as_i64());
        if expires_at.is_some_and(|ms| ms <= crate::vault::now_ms()) {
            bail!("secret {name}: the helper's token has expired; its owner (the program on the host whose login it is) must refresh it");
        }
        Ok(Answer { value, expires_at })
    }
}

/// One secret a helper serves: `NAME=FILE[#POINTER[#EXPIRES_POINTER]]` on its command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Served {
    pub name: String,
    pub file: String,
    pub pointer: Option<String>,
    pub expires_pointer: Option<String>,
}

impl std::str::FromStr for Served {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Served> {
        let (name, rest) = s.split_once('=').context("expected NAME=FILE[#POINTER[#EXPIRES_POINTER]]")?;
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            bail!("invalid secret name {name:?}");
        }
        let mut parts = rest.splitn(3, '#');
        let file = parts.next().filter(|f| !f.is_empty()).context("no file")?.to_string();
        let pointer = parts.next().map(String::from);
        let expires_pointer = parts.next().map(String::from);
        for p in pointer.iter().chain(&expires_pointer) {
            if !p.starts_with('/') {
                bail!("{p:?} is not a JSON pointer (one starts with /)");
            }
        }
        Ok(Served { name: name.into(), file, pointer, expires_pointer })
    }
}

/// The helper's answer to one request from a peer with uid `peer`: only a uid in `allowed` is
/// served, only a secret in `served`, and only its value and expiry.
pub fn answer(peer: u32, allowed: &[u32], served: &[Served], request: &str) -> serde_json::Value {
    if !allowed.contains(&peer) {
        return serde_json::json!({ "error": format!("uid {peer} may not ask this helper (it serves uid {})", list(allowed)) });
    }
    let name = serde_json::from_str::<serde_json::Value>(request).ok().and_then(|r| r.get("secret")?.as_str().map(String::from));
    let Some(name) = name else { return serde_json::json!({ "error": "expected {\"secret\": NAME}" }) };
    let Some(s) = served.iter().find(|s| s.name == name) else {
        return serde_json::json!({ "error": format!("this helper doesn't serve a secret {name:?}") });
    };
    match crate::vault::read_linked(&s.name, &s.file, s.pointer.as_deref(), s.expires_pointer.as_deref()) {
        Ok((value, expires_at)) => serde_json::json!({ "value": value, "expires_at": expires_at }),
        Err(e) => serde_json::json!({ "error": format!("{e:#}") }),
    }
}

fn list(uids: &[u32]) -> String {
    uids.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
}

/// Listens on `socket` (`@name` or a path). A path's stale socket is replaced, and the socket is
/// left connectable by anyone: each peer is checked by uid.
pub fn bind(socket: &str) -> Result<UnixListener> {
    if let Some(n) = socket.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        let a = std::os::unix::net::SocketAddr::from_abstract_name(n.as_bytes())?;
        return UnixListener::bind_addr(&a).with_context(|| format!("listening on {socket} (is another helper running?)"));
    }
    let _ = std::fs::remove_file(socket);
    let l = UnixListener::bind(socket).with_context(|| format!("listening on {socket}"))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666))?;
    Ok(l)
}

fn connect(socket: &str) -> std::io::Result<UnixStream> {
    if let Some(n) = socket.strip_prefix('@') {
        use std::os::linux::net::SocketAddrExt;
        let a = std::os::unix::net::SocketAddr::from_abstract_name(n.as_bytes())?;
        return UnixStream::connect_addr(&a);
    }
    UnixStream::connect(socket)
}

/// Serves `served` to `allowed` on `l` until the process ends: one thread per connection, one
/// request each. Each request is logged to stderr (names and uids, never values).
pub fn serve(l: UnixListener, allowed: Vec<u32>, served: Vec<Served>) -> Result<()> {
    let state = std::sync::Arc::new((allowed, served));
    for c in l.incoming() {
        let Ok(c) = c else { continue };
        let state = state.clone();
        std::thread::spawn(move || {
            if let Err(e) = serve_one(&c, &state.0, &state.1) {
                let _ = writeln!(std::io::stderr(), "wicket secret serve: {e:#}");
            }
        });
    }
    Ok(())
}

/// Answers one connection.
pub fn serve_one(c: &UnixStream, allowed: &[u32], served: &[Served]) -> Result<()> {
    c.set_read_timeout(Some(TIMEOUT))?;
    c.set_write_timeout(Some(TIMEOUT))?;
    let peer = peer_uid(c)?;
    let mut line = String::new();
    // A refused peer is answered without reading what it asks.
    if allowed.contains(&peer) {
        BufReader::new(c.take(MAX_REQUEST)).read_line(&mut line)?;
        // Hung up without asking (e.g. `wicket doctor`, or a vault that refused this helper's uid).
        if line.is_empty() {
            return Ok(());
        }
    }
    let a = answer(peer, allowed, served, line.trim());
    let what = serde_json::from_str::<serde_json::Value>(line.trim()).ok().and_then(|r| r.get("secret")?.as_str().map(String::from));
    match a.get("error").and_then(|e| e.as_str()) {
        // Not eprintln!: a closed stderr mustn't panic the helper (#422).
        Some(e) => {
            let _ = writeln!(
                std::io::stderr(),
                "wicket secret serve: uid {peer}{}: refused: {e}",
                what.map(|w| format!(" asked for {w}")).unwrap_or_default()
            );
        }
        None => {
            let _ = writeln!(std::io::stderr(), "wicket secret serve: served {} to uid {peer}", what.unwrap_or_default());
        }
    }
    let mut w = c;
    w.write_all(format!("{a}\n").as_bytes())?;
    Ok(())
}

/// The uid of the process at the other end of `s`, as the kernel reports it.
pub fn peer_uid(s: &UnixStream) -> Result<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: getsockopt writes at most `len` bytes into `cred`.
    let r =
        unsafe { libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut libc::c_void, &mut len) };
    if r != 0 {
        return Err(std::io::Error::last_os_error()).context("SO_PEERCRED");
    }
    Ok(cred.uid)
}

/// The uid of the user named `name`, from the user database (or `name` itself, if it is a number).
pub fn uid_of(name: &str) -> Option<u32> {
    if let Ok(n) = name.parse() {
        return Some(n);
    }
    let c = std::ffi::CString::new(name).ok()?;
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwnam_r fills `pw` with pointers into `buf`; only the uid is read.
    let r = unsafe { libc::getpwnam_r(c.as_ptr(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if r != 0 || out.is_null() {
        return None;
    }
    Some(pw.pw_uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn me() -> u32 {
        // SAFETY: a plain getter.
        unsafe { libc::geteuid() }
    }

    fn login(dir: &std::path::Path, token: &str, expires: i64) -> String {
        let f = dir.join("creds.json");
        std::fs::write(
            &f,
            format!(r#"{{"claudeAiOauth":{{"accessToken":"{token}","refreshToken":"rt-secret","expiresAt":{expires},"scopes":["a"]}}}}"#),
        )
        .unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        f.to_str().unwrap().to_string()
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-helper-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_served_secret_parses_from_its_flag() {
        let s: Served = "claude-login=/h/.claude/.credentials.json#/claudeAiOauth/accessToken#/claudeAiOauth/expiresAt".parse().unwrap();
        assert_eq!(s.name, "claude-login");
        assert_eq!(s.file, "/h/.claude/.credentials.json");
        assert_eq!(s.pointer.as_deref(), Some("/claudeAiOauth/accessToken"));
        assert_eq!(s.expires_pointer.as_deref(), Some("/claudeAiOauth/expiresAt"));
        let s: Served = "key=/k".parse().unwrap();
        assert_eq!((s.pointer, s.expires_pointer), (None, None));
        assert!("x".parse::<Served>().is_err());
        assert!("bad name=/k".parse::<Served>().is_err());
        assert!("k=/f#nopointer".parse::<Served>().is_err());
    }

    /// Only the uids it serves get an answer, and the answer is the pointed-to value and its
    /// expiry: never the refresh token, nor any other field of the file.
    #[test]
    fn the_helper_answers_only_wicketd_and_only_with_the_pointed_to_value() {
        let d = tmp("answer");
        let file = login(&d, "sk-access", 32503680000000);
        let served = vec![format!("claude-login={file}#/claudeAiOauth/accessToken#/claudeAiOauth/expiresAt").parse().unwrap()];
        let ask = r#"{"secret":"claude-login"}"#;

        let a = answer(1001, &[1001], &served, ask);
        assert_eq!(a, serde_json::json!({ "value": "sk-access", "expires_at": 32503680000000i64 }));
        let text = a.to_string();
        assert!(!text.contains("rt-secret") && !text.contains("scopes"), "{text}");

        let refused = answer(1002, &[1001], &served, ask);
        assert!(refused.get("value").is_none());
        assert!(refused["error"].as_str().unwrap().contains("uid 1002 may not ask"), "{refused}");

        let other = answer(1001, &[1001], &served, r#"{"secret":"other"}"#);
        assert!(other["error"].as_str().unwrap().contains("doesn't serve"), "{other}");
        assert!(answer(1001, &[1001], &served, "garbage")["error"].is_string());

        login(&d, "sk-old", 1);
        let expired = answer(1001, &[1001], &served, ask);
        assert!(expired["error"].as_str().unwrap().contains("expired"), "{expired}");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Over a real socket: the peer check uses the kernel's uid for the connecting process, and the
    /// vault side refuses a helper that runs as anyone but the link's uid.
    #[test]
    fn the_peer_check_uses_the_kernels_uid_at_both_ends() {
        let d = tmp("socket");
        let file = login(&d, "sk-live", 32503680000000);
        let served: Vec<Served> = vec![format!("claude-login={file}#/claudeAiOauth/accessToken#/claudeAiOauth/expiresAt").parse().unwrap()];
        let me = me();

        // Served to this uid: the vault's side gets the value and its expiry.
        let sock = format!("@wicket-secret-test.{}.served", std::process::id());
        let l = bind(&sock).unwrap();
        let s2 = served.clone();
        std::thread::spawn(move || serve(l, vec![me], s2));
        let h = HelperRef { uid: me, socket: sock.clone() };
        let a = h.fetch("claude-login").unwrap();
        assert_eq!(a, Answer { value: "sk-live".into(), expires_at: Some(32503680000000) });
        assert!(!format!("{a:?}").contains("sk-live"), "an answer never prints its value");
        // The helper re-reads the file: a refresh is picked up at once.
        login(&d, "sk-refreshed", 32503680000000);
        assert_eq!(h.fetch("claude-login").unwrap().value, "sk-refreshed");

        // A helper that serves only another uid refuses this one.
        let sock2 = format!("@wicket-secret-test.{}.other", std::process::id());
        let l = bind(&sock2).unwrap();
        let s3 = served.clone();
        std::thread::spawn(move || serve(l, vec![me.wrapping_add(1)], s3));
        let e = HelperRef { uid: me, socket: sock2 }.fetch("claude-login").unwrap_err();
        assert!(format!("{e:#}").contains(&format!("uid {me} may not ask")), "{e:#}");

        // The link names another uid than the helper's: the vault refuses its answer.
        let e = HelperRef { uid: me.wrapping_add(1), socket: sock.clone() }.fetch("claude-login").unwrap_err();
        assert!(format!("{e:#}").contains(&format!("held by uid {me}")), "{e:#}");

        // No helper there: says so, and how to start one.
        let e = HelperRef { uid: me, socket: format!("@wicket-secret-test.{}.none", std::process::id()) }.fetch("x").unwrap_err();
        assert!(format!("{e:#}").contains("isn't reachable") && format!("{e:#}").contains("wicket secret serve"), "{e:#}");

        // A path socket works too.
        let path = d.join("helper.sock");
        let l = bind(path.to_str().unwrap()).unwrap();
        std::thread::spawn(move || serve(l, vec![me], served));
        assert_eq!(HelperRef { uid: me, socket: path.to_str().unwrap().into() }.fetch("claude-login").unwrap().value, "sk-refreshed");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_uid_is_found_by_number_or_name() {
        assert_eq!(uid_of("1234"), Some(1234));
        assert_eq!(uid_of("no-such-user-wicket-test"), None);
    }
}
