//! Secrets and budget slices a node holds for the runs it serves (#152), and its queue of asks
//! raised while cut off (#153).
//!
//! - **Only what is used, only in memory.** A secret comes to a node only when one of its runs first
//!   needs it (its model route, or an `inject` rule for a host it reaches): the node asks the control
//!   host over that run's own connection, and the control host releases it only if the run's zone
//!   names it, the vault holds it and its host binding covers the hosts the zone uses it for, and
//!   audits it (`node.secret_fetch`). It is never prefetched, and never sent for another run, zone or
//!   node. The node keeps it in this process's memory only (locked against swap, zeroed when dropped,
//!   the process not dumpable, never logged), never on disk, encrypted or not. The Claude login goes as
//!   its current access token only; the refresh token and refreshing stay on the control host.
//! - **How long.** A run's use of a secret lasts until the run's authority ends (its token's block 0),
//!   or the upstream token's own expiry if earlier. The node drops a secret when the last run that
//!   used it ends or can no longer use it, and when the control host says it changed or was removed
//!   (it checks every 2 s while connected): the next use fetches it again.
//! - **Refused, not set yet** (#415). A run's zone is fixed at start, but the vault isn't: an optional
//!   injection whose secret isn't set yet is refused by the control host, and the node remembers that
//!   for the run (never a value) for [`REFUSAL_HELD_MS`], so a run's requests don't each ask again.
//!   The control host says when such a secret becomes available (as a change, [`crate::chan::Msg::SecretRevoke`]),
//!   and the next use fetches it; a control host that doesn't say is asked again once the refusal is
//!   that old.
//! - **Cut off.** A secret already held keeps working; one first needed while the control host is
//!   unreachable fails clearly, and is audited, until it is back. A restart of `serve` while cut off
//!   loses the cache: credentialed hosts and model calls stop until the control host is back, while
//!   plain egress the token allows goes on until its grants expire. A self-update's re-exec hands
//!   the cache to the new process through a sealed memfd, never a file ([`Cache::export`]).
//! - **Budget slices** are sent per run ([`crate::chan::Msg::BudgetSlice`]) and kept on the node's
//!   disk (they aren't secret), so a restart doesn't hand an offline node a fresh one.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use wicket_proxy::llm::Slice;
use zeroize::Zeroize;

/// A secret released to a node for one run (over the run's authenticated channel).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fetched {
    pub name: String,
    pub value: String,
    /// The hosts it may be sent to (the vault's binding, enforced on the node too).
    pub hosts: Vec<String>,
    /// wicket's expiry for this run's use of it (Unix ms): the run's authority.
    pub not_after: i64,
    /// The upstream token's own expiry (Unix ms), if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_expiry: Option<i64>,
}

impl std::fmt::Debug for Fetched {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fetched").field("name", &self.name).field("hosts", &self.hosts).field("not_after", &self.not_after).finish()
    }
}

impl Drop for Fetched {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// The secrets a zone may use on a node, with the hosts it uses each for: its model credential (for
/// the model upstream's host) and its injected secrets (for their rules' hosts).
pub fn zone_secrets(zone: &wicket_core::ZoneSpec) -> BTreeMap<String, Vec<String>> {
    let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if let Some(l) = &zone.llm {
        let host = reqwest::Url::parse(&l.upstream).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_default();
        m.entry(l.secret.clone()).or_default().push(host);
    }
    for r in &zone.inject {
        m.entry(r.secret.clone()).or_default().push(r.host.clone());
    }
    m
}

/// Whether `zone`, or one of the run's credential swaps, uses vault secret `name` (#415: the control
/// host tracks a refusal of only such a name).
pub fn zone_uses(zone: &wicket_core::ZoneSpec, swaps: &[wicket_proxy::CredentialSwap], name: &str) -> bool {
    zone_secrets(zone).contains_key(name) || swaps.iter().any(|s| matches!(&s.real, wicket_proxy::SwapSource::Vault(n) if n == name))
}

/// The control host's side: whether run `run` (in `zone`) may have `name` on its node, and if so the
/// secret, until `not_after` (Unix ms). Refused unless the zone names it, the vault holds it, and its
/// binding covers every host the zone uses it for.
#[cfg(test)]
pub fn release(zone: &wicket_core::ZoneSpec, vault: &wicket_proxy::vault::Vault, name: &str, not_after: i64) -> Result<Fetched, String> {
    release_run(zone, &[], vault, name, not_after)
}

/// [`release`] for a run with credential swaps (#257), which its node makes: a vault secret a swap
/// names is released as one the zone uses for the swap's hosts (its binding must cover them), and a
/// swap's value (`chan::SwapReal::Value`, fetched by its key) is released bound to its swap's hosts
/// alone. Nothing else of the run's swaps is ever released.
pub fn release_run(
    zone: &wicket_core::ZoneSpec,
    swaps: &[wicket_proxy::CredentialSwap],
    vault: &wicket_proxy::vault::Vault,
    name: &str,
    not_after: i64,
) -> Result<Fetched, String> {
    let value = swaps.iter().enumerate().find_map(|(i, s)| match &s.real {
        wicket_proxy::SwapSource::Value(v) if crate::chan::swap_value_key(i) == name => Some((s, v)),
        _ => None,
    });
    if let Some((s, value)) = value {
        if value.is_empty() {
            return Err(format!("the {} swap has no value", s.name));
        }
        return Ok(Fetched { name: name.into(), value: value.clone(), hosts: vec![s.host.clone()], not_after, upstream_expiry: None });
    }
    let mut uses = zone_secrets(zone);
    for s in swaps {
        if let wicket_proxy::SwapSource::Vault(n) = &s.real {
            uses.entry(n.clone()).or_default().push(s.host.clone());
        }
    }
    let Some(hosts_used) = uses.get(name) else { return Err(format!("zone {} doesn't use secret {name}", zone.name)) };
    for h in hosts_used {
        vault.check(name, h).map_err(|e| e.to_string())?;
    }
    let value = vault.get(name).map_err(|e| e.to_string())?;
    Ok(Fetched { name: name.into(), value, hosts: vault.hosts(name), not_after, upstream_expiry: vault.expires_at(name) })
}

/// A secret released for a registry pull only (#191: a node pulling a box's image): the vault's
/// binding must cover every host it may be sent to, `hosts` (`host[:port]`; the port doesn't count).
pub fn release_for_hosts(vault: &wicket_proxy::vault::Vault, name: &str, hosts: &[String], not_after: i64) -> Result<Fetched, String> {
    let bare = |h: &str| -> String {
        match h.rsplit_once(':') {
            Some((a, p)) if p.chars().all(|c| c.is_ascii_digit()) => a.trim_start_matches('[').trim_end_matches(']').to_string(),
            _ => h.to_string(),
        }
    };
    let hosts: Vec<String> = hosts.iter().map(|h| bare(h)).collect();
    for h in &hosts {
        vault.check(name, h).map_err(|e| e.to_string())?;
    }
    let value = vault.get(name).map_err(|e| e.to_string())?;
    Ok(Fetched { name: name.into(), value, hosts, not_after, upstream_expiry: vault.expires_at(name) })
}

/// What the control host last released, to tell a change (rotation, removal, rebinding) from none.
pub fn digest(f: &Fetched) -> String {
    use sha2::Digest;
    let mut d = sha2::Sha256::default();
    d.update(f.value.as_bytes());
    d.update(serde_json::to_vec(&(&f.hosts, f.upstream_expiry)).unwrap_or_default());
    hex::encode(d.finalize())
}

/// A secret's bytes in memory: locked against swap while held, zeroed when dropped.
struct Locked(Box<[u8]>);

impl Locked {
    fn new(v: &str) -> Locked {
        let b: Box<[u8]> = v.as_bytes().into();
        if !b.is_empty() {
            // SAFETY: locks this allocation's own pages; it outlives the lock (unlocked in drop).
            unsafe { libc::mlock(b.as_ptr().cast(), b.len()) };
        }
        Locked(b)
    }

    fn text(&self) -> Result<String> {
        String::from_utf8(self.0.to_vec()).context("secret is not text")
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        self.0.zeroize();
        if !self.0.is_empty() {
            // SAFETY: the same allocation locked in `new`.
            unsafe { libc::munlock(self.0.as_ptr().cast(), self.0.len()) };
        }
    }
}

struct Entry {
    value: Locked,
    hosts: Vec<String>,
    upstream_expiry: Option<i64>,
    /// The runs that fetched it, and until when each may use it (Unix ms).
    users: HashMap<String, i64>,
    /// Users given it by [`Cache::share`] rather than fetching it (a child the node started), and
    /// the run each was shared from: a revoke for that run ends theirs too.
    shared_from: HashMap<String, String>,
}

impl Entry {
    /// Ends `run`'s use, and the uses shared from it (and from those, a child's child).
    fn drop_user(&mut self, run: &str) {
        let mut gone = vec![run.to_string()];
        while let Some(r) = gone.pop() {
            self.users.remove(&r);
            self.shared_from.remove(&r);
            gone.extend(self.shared_from.iter().filter(|(_, from)| **from == r).map(|(to, _)| to.clone()));
        }
    }
}

/// Why a node didn't get a secret from its control host.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unfetched {
    /// The control host answered no: the zone doesn't use it, the vault doesn't hold it (yet), or its
    /// binding doesn't cover the hosts the zone uses it for. Remembered for the run a while (#415).
    Refused(String),
    /// It couldn't be asked, or didn't answer: the next use asks again.
    Unreachable(String),
}

impl std::fmt::Display for Unfetched {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unfetched::Refused(w) | Unfetched::Unreachable(w) => f.write_str(w),
        }
    }
}

/// How a node fetches a secret for a run: over the run's own connection to its control host.
pub type Fetcher = Arc<dyn Fn(String, String) -> futures_util::future::BoxFuture<'static, Result<Fetched, Unfetched>> + Send + Sync>;

/// How long a node takes a control host's refusal of a secret for a run as its answer (#415), unless
/// the control host says sooner that the secret changed: it does within about 2 s.
pub const REFUSAL_HELD_MS: i64 = 30_000;

/// How long a node fails a secret's fetch at once after its control host couldn't be asked (#415),
/// so a box's requests while cut off (or over a dead link not yet noticed) don't each wait for it.
pub const UNREACHABLE_HELD_MS: i64 = 2_000;

/// How many times a fetch is made again when a revoke overtook its answer (#415).
const OVERTAKEN_TRIES: usize = 3;

/// One fetch in flight for a run and a secret.
type Inflight = Arc<tokio::sync::Mutex<()>>;

/// The node's secret cache: in this process's memory only.
pub struct Cache {
    entries: Mutex<HashMap<String, Entry>>,
    clock: wicket_proxy::decide::Clock,
    /// One fetch at a time per run and secret: concurrent first uses share it.
    inflight: Mutex<HashMap<(String, String), Inflight>>,
    /// Secrets the control host refused a run, or couldn't be asked for (#415), by run and name:
    /// until when that answer holds, and why. Never a value.
    refused: Mutex<HashMap<(String, String), (i64, String)>>,
    /// Revokes so far, by run and name (#415): an answer to a fetch that a revoke overtook is
    /// stale, and not taken.
    revokes: Mutex<HashMap<(String, String), u64>>,
}

/// Where a self-update's re-exec finds the cache handed over (#162): a sealed memfd's descriptor.
pub const HANDOVER_ENV: &str = "WICKET_NODE_SECRETS_FD";

/// The cache's handed-over form (in a memfd, never a file).
#[derive(Serialize, Deserialize)]
struct Handed {
    name: String,
    value: String,
    hosts: Vec<String>,
    upstream_expiry: Option<i64>,
    users: HashMap<String, i64>,
    #[serde(default)]
    shared_from: HashMap<String, String>,
}

impl Drop for Handed {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl Cache {
    pub fn new(clock: wicket_proxy::decide::Clock) -> Arc<Cache> {
        Arc::new(Cache {
            entries: Mutex::new(HashMap::new()),
            clock,
            inflight: Mutex::new(HashMap::new()),
            refused: Mutex::new(HashMap::new()),
            revokes: Mutex::new(HashMap::new()),
        })
    }

    /// Keeps this process's memory out of core dumps and `ptrace` attach by other processes of the
    /// same user (root still can). Called once by `node serve`.
    pub fn harden_process() {
        // SAFETY: a plain prctl on this process.
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
    }

    fn usable(&self, e: &Entry, run: &str) -> bool {
        let now = (self.clock)();
        e.users.get(run).is_some_and(|u| *u > now) && e.upstream_expiry.is_none_or(|u| u > now)
    }

    /// Takes a secret fetched for `run`.
    pub fn put(&self, run: &str, f: &Fetched) {
        let mut m = self.entries.lock().expect("cache");
        let e = m.entry(f.name.clone()).or_insert_with(|| Entry {
            value: Locked::new(&f.value),
            hosts: vec![],
            upstream_expiry: None,
            users: HashMap::new(),
            shared_from: HashMap::new(),
        });
        if e.value.0.as_ref() != f.value.as_bytes() {
            e.value = Locked::new(&f.value);
        }
        e.hosts = f.hosts.clone();
        e.upstream_expiry = f.upstream_expiry;
        e.users.insert(run.into(), f.not_after);
        // Fetched for itself now, not shared: a revoke for its parent no longer ends it.
        e.shared_from.remove(run);
    }

    /// A child the node started for `from`'s box (#164) uses the secrets in `names` that `from`
    /// holds, until `until` (Unix ms, at most the child's authority): never one its parent doesn't
    /// hold, never longer than its parent's use. Until the control host takes the child over, it
    /// fetches nothing of its own.
    pub fn share(&self, from: &str, to: &str, names: &[String], until: i64) -> Vec<String> {
        let mut m = self.entries.lock().expect("cache");
        let mut shared = vec![];
        for n in names {
            if let Some(e) = m.get_mut(n) {
                if let Some(u) = e.users.get(from).copied() {
                    e.users.insert(to.into(), u.min(until));
                    e.shared_from.insert(to.into(), from.into());
                    shared.push(n.clone());
                }
            }
        }
        shared
    }

    /// Run `run` no longer uses `name` (the control host says it changed or was removed), nor do the
    /// runs it was shared with: dropped if no run uses it any more. A refusal of it is forgotten too
    /// (it may have been set since, #415), and a fetch in flight for it is stale: the next use asks
    /// again.
    pub fn revoke(&self, run: &str, name: &str) {
        let key = (run.to_string(), name.to_string());
        *self.revokes.lock().expect("revokes").entry(key.clone()).or_default() += 1;
        self.refused.lock().expect("refused").remove(&key);
        let mut m = self.entries.lock().expect("cache");
        if let Some(e) = m.get_mut(name) {
            e.drop_user(run);
            if e.users.is_empty() {
                m.remove(name);
            }
        }
    }

    /// A run has ended: every secret only it used is dropped.
    pub fn release(&self, run: &str) {
        self.refused.lock().expect("refused").retain(|(r, _), _| r != run);
        self.revokes.lock().expect("revokes").retain(|(r, _), _| r != run);
        let mut m = self.entries.lock().expect("cache");
        m.retain(|_, e| {
            e.users.remove(run);
            !e.users.is_empty()
        });
    }

    /// Drops what has expired: runs' uses past their authority, secrets past their upstream expiry,
    /// and secrets no run may use any more.
    pub fn sweep(&self) {
        let now = (self.clock)();
        let mut m = self.entries.lock().expect("cache");
        m.retain(|_, e| {
            e.users.retain(|_, u| *u > now);
            !e.users.is_empty() && e.upstream_expiry.is_none_or(|u| u > now)
        });
    }

    /// The names held (never values).
    #[cfg(test)]
    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.entries.lock().expect("cache").keys().cloned().collect();
        v.sort();
        v
    }

    /// Run `run`'s view, for its proxies' vault, fetching through `fetch` on first use.
    pub fn source(self: &Arc<Self>, run: &str, fetch: Fetcher) -> Arc<dyn wicket_proxy::vault::SecretSource> {
        Arc::new(RunSecrets { cache: self.clone(), run: run.into(), fetch })
    }

    /// Hands the cache over to a re-exec'd `serve` (#162): a memfd holding it, sealed against any
    /// change, its close-on-exec flag cleared, so only the exec'd process inherits it. The caller
    /// passes its number in [`HANDOVER_ENV`].
    pub fn export(&self) -> Result<OwnedFd> {
        let handed: Vec<Handed> = self
            .entries
            .lock()
            .expect("cache")
            .iter()
            .map(|(n, e)| {
                Ok(Handed {
                    name: n.clone(),
                    value: e.value.text()?,
                    hosts: e.hosts.clone(),
                    upstream_expiry: e.upstream_expiry,
                    users: e.users.clone(),
                    shared_from: e.shared_from.clone(),
                })
            })
            .collect::<Result<_>>()?;
        let mut bytes = serde_json::to_vec(&handed)?;
        drop(handed);
        let name = c"wicket-node-secrets";
        // SAFETY: memfd_create with a valid C string; the fd is owned from here.
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
        if fd < 0 {
            bytes.zeroize();
            bail!("memfd_create: {}", std::io::Error::last_os_error());
        }
        // SAFETY: fd was just created and is ours.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut f = std::fs::File::from(owned.try_clone()?);
        let w = std::io::Write::write_all(&mut f, &bytes);
        bytes.zeroize();
        w?;
        let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        // SAFETY: fcntl on our own fd.
        if unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
            bail!("sealing the memfd: {}", std::io::Error::last_os_error());
        }
        // Inherited across the exec only: the caller execs right after this.
        // SAFETY: fcntl on our own fd.
        unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFD, 0) };
        Ok(owned)
    }

    /// Takes the cache handed over by the process that exec'd this one, if any: [`HANDOVER_ENV`]
    /// names a sealed memfd, which is read, then closed. Anything else there is refused.
    pub fn import_handover(&self) -> Result<usize> {
        let Some(n) = std::env::var(HANDOVER_ENV).ok().and_then(|v| v.parse::<i32>().ok()) else { return Ok(0) };
        std::env::remove_var(HANDOVER_ENV);
        // SAFETY: the descriptor the previous process left open for this one; owned from here.
        let owned = unsafe { OwnedFd::from_raw_fd(n) };
        self.import(owned)
    }

    fn import(&self, fd: OwnedFd) -> Result<usize> {
        // SAFETY: fcntl on a descriptor we own.
        let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
        let want = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
        if seals < 0 || seals & want != want {
            bail!("the handed-over descriptor is not a sealed memfd");
        }
        let mut f = std::fs::File::from(fd);
        std::io::Seek::seek(&mut f, std::io::SeekFrom::Start(0))?;
        let mut bytes = vec![];
        std::io::Read::read_to_end(&mut f, &mut bytes)?;
        let parsed: Result<Vec<Handed>, _> = serde_json::from_slice(&bytes);
        bytes.zeroize();
        let handed = parsed.context("the handed-over cache")?;
        let n = handed.len();
        let mut m = self.entries.lock().expect("cache");
        for h in handed {
            m.insert(
                h.name.clone(),
                Entry {
                    value: Locked::new(&h.value),
                    hosts: h.hosts.clone(),
                    upstream_expiry: h.upstream_expiry,
                    users: h.users.clone(),
                    shared_from: h.shared_from.clone(),
                },
            );
        }
        Ok(n)
    }
}

struct RunSecrets {
    cache: Arc<Cache>,
    run: String,
    fetch: Fetcher,
}

impl wicket_proxy::vault::SecretSource for RunSecrets {
    fn get(&self, name: &str) -> Result<String> {
        let m = self.cache.entries.lock().expect("cache");
        match m.get(name) {
            Some(e) if self.cache.usable(e, &self.run) => e.value.text(),
            _ => bail!("secret {name:?} is not cached on this node for this run"),
        }
    }

    fn hosts(&self, name: &str) -> Vec<String> {
        let m = self.cache.entries.lock().expect("cache");
        m.get(name).filter(|e| self.cache.usable(e, &self.run)).map(|e| e.hosts.clone()).unwrap_or_default()
    }

    fn has(&self, name: &str) -> bool {
        let m = self.cache.entries.lock().expect("cache");
        m.get(name).is_some_and(|e| self.cache.usable(e, &self.run))
    }

    fn fetch<'a>(&'a self, name: &'a str) -> futures_util::future::BoxFuture<'a, Result<()>> {
        Box::pin(self.fetch_from_control_host(name, false))
    }

    /// The upstream refused the value held (#360): ask the control host for the current one, even
    /// though it is held (it may not have said yet that the secret changed).
    fn refetch<'a>(&'a self, name: &'a str) -> futures_util::future::BoxFuture<'a, Result<()>> {
        Box::pin(self.fetch_from_control_host(name, true))
    }
}

impl RunSecrets {
    /// Fetches `name` for this run, one fetch at a time per run and name: if it isn't held, or
    /// always with `again`.
    async fn fetch_from_control_host(&self, name: &str, again: bool) -> Result<()> {
        let lock = {
            let mut m = self.cache.inflight.lock().expect("inflight");
            m.entry((self.run.clone(), name.to_string())).or_default().clone()
        };
        let _one = lock.lock().await;
        if !again && wicket_proxy::vault::SecretSource::has(self, name) {
            return Ok(());
        }
        let key = (self.run.clone(), name.to_string());
        if !again {
            // Refused, or unreachable, a moment ago (#415): the same answer, without asking again on
            // every request.
            let now = (self.cache.clock)();
            if let Some((_, why)) = self.cache.refused.lock().expect("refused").get(&key).filter(|(until, _)| now < *until) {
                bail!("{why}");
            }
        }
        for _ in 0..OVERTAKEN_TRIES {
            let revokes = self.cache.revokes.lock().expect("revokes").get(&key).copied().unwrap_or(0);
            let answer = (self.fetch)(self.run.clone(), name.to_string()).await;
            // A revoke that came while this was asked makes its answer stale (#415): ask again.
            if self.cache.revokes.lock().expect("revokes").get(&key).copied().unwrap_or(0) != revokes {
                continue;
            }
            let now = (self.cache.clock)();
            return match answer {
                Ok(f) if f.name == name => {
                    self.cache.refused.lock().expect("refused").remove(&key);
                    self.cache.put(&self.run, &f);
                    Ok(())
                }
                Ok(_) => bail!("the control host sent another secret"),
                Err(e) => {
                    let held = match &e {
                        Unfetched::Refused(_) => REFUSAL_HELD_MS,
                        Unfetched::Unreachable(_) => UNREACHABLE_HELD_MS,
                    };
                    self.cache.refused.lock().expect("refused").insert(key, (now + held, e.to_string()));
                    bail!("{e}")
                }
            };
        }
        bail!("secret {name:?} kept changing on the control host while it was fetched")
    }
}

/// Budget slices as last sent, per run, under `<node dir>/slices/` (not secret).
pub struct Slices {
    dir: PathBuf,
}

impl Slices {
    pub fn new(root: &Path) -> Result<Slices> {
        let dir = root.join("slices");
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(Slices { dir })
    }

    fn file(&self, run: &str) -> Result<PathBuf> {
        crate::check_run_id(run)?;
        Ok(self.dir.join(format!("{run}.json")))
    }

    pub fn put(&self, run: &str, s: &Slice) -> Result<()> {
        crate::files::write_atomic(&self.file(run)?, &serde_json::to_vec(s)?)
    }

    pub fn get(&self, run: &str) -> Option<Slice> {
        std::fs::read(self.file(run).ok()?).ok().and_then(|b| serde_json::from_slice(&b).ok())
    }

    pub fn drop_run(&self, run: &str) {
        if let Ok(f) = self.file(run) {
            let _ = std::fs::remove_file(f);
        }
    }
}

/// Asks raised on a node while its control host was unreachable (#153), kept until it answers.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QueuedAsk {
    /// Node-local id (`q-…`).
    pub id: String,
    pub run: String,
    pub op: wicket_core::Op,
    pub why: String,
    #[serde(default)]
    pub who: Option<serde_json::Value>,
    /// When it was raised (Unix ms, node clock).
    pub at: i64,
    /// For every path under the op's directory (`request_access`'s `scope: prefix`, #164).
    #[serde(default)]
    pub prefix: bool,
}

/// The node's queue of asks, on its disk (`asks.json`), deduplicated by run and op.
pub struct Asks {
    file: PathBuf,
    held: Mutex<BTreeMap<String, QueuedAsk>>,
}

impl Asks {
    pub fn open(root: &Path) -> Asks {
        let file = root.join("asks.json");
        let held = std::fs::read(&file).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        Asks { file, held: Mutex::new(held) }
    }

    fn save(&self, held: &BTreeMap<String, QueuedAsk>) {
        let _ = crate::files::write_atomic(&self.file, &serde_json::to_vec(held).unwrap_or_default());
    }

    /// Queues an ask (or finds the one already queued for the same run and op): its id, and
    /// whether it is new.
    pub fn push(
        &self,
        run: &str,
        op: &wicket_core::Op,
        why: &str,
        who: Option<&serde_json::Value>,
        at: i64,
        prefix: bool,
    ) -> (String, bool) {
        let mut held = self.held.lock().expect("asks");
        let digest = hex::encode(op.digest());
        if let Some(q) = held.values().find(|q| q.run == run && q.prefix == prefix && hex::encode(q.op.digest()) == digest) {
            return (q.id.clone(), false);
        }
        // A prefix ask is another request than the one path's (as in the ledger).
        let id = match prefix {
            false => format!("q-{}", &digest[..12]),
            true => format!("q-{}p", &digest[..11]),
        };
        held.insert(
            id.clone(),
            QueuedAsk { id: id.clone(), run: run.into(), op: op.clone(), why: why.into(), who: who.cloned(), at, prefix },
        );
        self.save(&held);
        (id, true)
    }

    /// The queued asks of `run`.
    pub fn of(&self, run: &str) -> Vec<QueuedAsk> {
        self.held.lock().expect("asks").values().filter(|q| q.run == run).cloned().collect()
    }

    pub fn get(&self, id: &str) -> Option<QueuedAsk> {
        self.held.lock().expect("asks").get(id).cloned()
    }

    /// Done with an ask (the control host raised it, or the run has ended).
    pub fn remove(&self, id: &str) {
        let mut held = self.held.lock().expect("asks");
        if held.remove(id).is_some() {
            self.save(&held);
        }
    }

    pub fn drop_run(&self, run: &str) {
        let mut held = self.held.lock().expect("asks");
        let n = held.len();
        held.retain(|_, q| q.run != run);
        if held.len() != n {
            self.save(&held);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
    use wicket_proxy::vault::Vault;

    const RA: &str = "run_aaaaaaaaaaaaaaaaaaaaaaaaaa";
    const RB: &str = "run_bbbbbbbbbbbbbbbbbbbbbbbbbb";
    const VALUE: &str = "ghp_wicket-test-not-a-real-token";

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("wicket-nodesecrets-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn zone(y: &str) -> wicket_core::ZoneSpec {
        wicket_core::yaml::from_str(y).unwrap()
    }

    /// The control host's vault, and a fetcher that releases from it as the control host does,
    /// counting fetches, or fails as an unreachable one does.
    fn control(d: &Path) -> Vault {
        let v = Vault::new(d.join("vault"));
        v.set("gh", VALUE).unwrap();
        v.set_hosts("gh", &["api.github.com".into()]).unwrap();
        v.set("other", "x-other").unwrap();
        v.set_hosts("other", &["api.github.com".into()]).unwrap();
        v
    }

    #[test]
    fn a_registry_secret_is_released_only_for_hosts_its_binding_covers() {
        let d = tmp("registry");
        let v = Vault::new(d.join("vault"));
        v.set("reg", "u:p").unwrap();
        v.set_hosts("reg", &["registry.example.com".into(), "auth.example.com".into()]).unwrap();
        let f = release_for_hosts(&v, "reg", &["registry.example.com:5000".into(), "auth.example.com".into()], 1).unwrap();
        assert_eq!((f.value.as_str(), f.hosts.clone()), ("u:p", vec!["registry.example.com".to_string(), "auth.example.com".to_string()]));
        assert!(release_for_hosts(&v, "reg", &["registry.example.com".into(), "elsewhere.example.com".into()], 1).is_err());
        assert!(release_for_hosts(&v, "missing", &["registry.example.com".into()], 1).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// #257: a run's swaps are released to its node for their hosts only: a vault secret a swap
    /// names if its binding covers the swap's host, a swap's value by its key (bound to its host),
    /// and nothing for another run's key or a swap the binding doesn't cover.
    #[test]
    fn a_swap_is_released_only_for_its_hosts() {
        let d = tmp("swaps");
        let v = control(&d);
        let z = zone("name: z\n");
        let swap = |host: &str, real: wicket_proxy::SwapSource| wicket_proxy::CredentialSwap {
            name: "login".into(),
            host: host.into(),
            placeholder: "ph".into(),
            real,
            box_bearers: false,
        };
        let swaps = vec![
            swap("api.github.com", wicket_proxy::SwapSource::Vault("gh".into())),
            swap("sessions.example.com", wicket_proxy::SwapSource::Value("sess-1".into())),
        ];
        let f = release_run(&z, &swaps, &v, "gh", 1).unwrap();
        assert_eq!((f.value.as_str(), f.hosts.clone()), (VALUE, vec!["api.github.com".to_string()]));
        let f = release_run(&z, &swaps, &v, "swap.1", 1).unwrap();
        assert_eq!((f.value.as_str(), f.hosts.clone(), f.upstream_expiry), ("sess-1", vec!["sessions.example.com".to_string()], None));
        // Not a value's key: swap 0 is a vault secret's, and there is no swap 2.
        assert!(release_run(&z, &swaps, &v, "swap.0", 1).is_err());
        assert!(release_run(&z, &swaps, &v, "swap.2", 1).is_err());
        // Without the swap, the zone doesn't use it; with it toward a host its binding doesn't cover, refused.
        assert!(release(&z, &v, "gh", 1).unwrap_err().contains("doesn't use"));
        let wide = vec![swap("elsewhere.example.com", wicket_proxy::SwapSource::Vault("gh".into()))];
        assert!(release_run(&z, &wide, &v, "gh", 1).unwrap_err().contains("elsewhere.example.com"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    fn fetcher(v: Vault, z: wicket_core::ZoneSpec, up: Arc<AtomicI64>, calls: Arc<AtomicU64>) -> Fetcher {
        Arc::new(move |_run, name| {
            let (v, z, up, calls) = (v.clone(), z.clone(), up.clone(), calls.clone());
            Box::pin(async move {
                calls.fetch_add(1, Ordering::SeqCst);
                if up.load(Ordering::SeqCst) == 0 {
                    return Err(Unfetched::Unreachable("credential not cached on this node; control host unreachable".into()));
                }
                release(&z, &v, &name, 60_000).map_err(Unfetched::Refused)
            })
        })
    }

    /// #152: a node holds only the secrets its runs used, fetched once each, in memory only; a first
    /// use while cut off fails clearly; a secret goes when its last user ends.
    #[tokio::test]
    async fn the_cache_holds_only_what_runs_used_fetched_once_and_never_on_disk() {
        let d = tmp("cache");
        let v = control(&d);
        let za = zone("name: za\ninject: [{ host: api.github.com, header: authorization, format: 'Bearer {secret}', secret: gh }]\n");
        let zb = zone("name: zb\ninject: [{ host: api.github.com, header: authorization, format: 'Bearer {secret}', secret: other }]\n");
        let (up, calls) = (Arc::new(AtomicI64::new(1)), Arc::new(AtomicU64::new(0)));
        let now = Arc::new(AtomicI64::new(1_000));
        let cache = Cache::new({
            let now = now.clone();
            Arc::new(move || now.load(Ordering::SeqCst))
        });
        let a = Vault::from_source(cache.source(RA, fetcher(v.clone(), za.clone(), up.clone(), calls.clone())));
        let b = Vault::from_source(cache.source(RB, fetcher(v.clone(), zb.clone(), up.clone(), calls.clone())));
        assert!(cache.names().is_empty(), "nothing prefetched");
        for _ in 0..5 {
            a.ensure("gh").await.unwrap();
            assert_eq!(a.get_for("gh", "api.github.com").unwrap(), VALUE);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "fetched once, not per request");
        assert!(a.get_for("gh", "evil.example").is_err(), "the binding travels with it");
        assert!(a.ensure("other").await.is_err(), "run a's zone doesn't use it: the control host refuses");
        assert!(!b.has("gh"), "another run's secret isn't this run's");
        assert_eq!(cache.names(), ["gh"], "only what was used");
        // Cut off: what is held keeps working; a first use fails clearly.
        up.store(0, Ordering::SeqCst);
        assert_eq!(a.get("gh").unwrap(), VALUE);
        let e = b.ensure("other").await.unwrap_err().to_string();
        assert!(e.contains("not cached on this node") && e.contains("unreachable"), "{e}");
        // Each use while cut off fails at once for a moment, rather than wait on the control host.
        assert!(b.ensure("other").await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 3, "not asked again at once");
        up.store(1, Ordering::SeqCst);
        now.fetch_add(UNREACHABLE_HELD_MS, Ordering::SeqCst);
        b.ensure("other").await.unwrap();
        assert_eq!(cache.names(), ["gh", "other"]);
        // A run ends: what only it used goes.
        cache.release(RB);
        assert_eq!(cache.names(), ["gh"]);
        // Changed on the control host: dropped; the next use fetches it again.
        cache.revoke(RA, "gh");
        assert!(cache.names().is_empty());
        a.ensure("gh").await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        // Never on disk: nothing but the control host's own vault, in this test's directory, holds it.
        std::fs::remove_dir_all(d.join("vault")).unwrap();
        assert!(!grep_tree(&d, VALUE), "the value reached a file");
        let _ = std::fs::remove_dir_all(d);
    }

    /// #360: an upstream refused the value a node holds (the login refreshed on the control host,
    /// which hasn't said so yet): a refetch asks the control host again though the value is held,
    /// and takes the new value; a plain `ensure` still doesn't.
    #[tokio::test]
    async fn a_refetch_asks_the_control_host_again_though_held() {
        let d = tmp("refetch");
        let v = control(&d);
        let z = zone("name: za\ninject: [{ host: api.github.com, header: authorization, format: 'Bearer {secret}', secret: gh }]\n");
        let (up, calls) = (Arc::new(AtomicI64::new(1)), Arc::new(AtomicU64::new(0)));
        let cache = Cache::new(Arc::new(|| 1_000));
        let a = Vault::from_source(cache.source(RA, fetcher(v.clone(), z, up, calls.clone())));
        a.ensure("gh").await.unwrap();
        v.set("gh", "ghp_wicket-test-refreshed").unwrap();
        a.ensure("gh").await.unwrap();
        assert_eq!((a.get("gh").unwrap().as_str(), calls.load(Ordering::SeqCst)), (VALUE, 1), "held: not fetched again");
        a.refetch("gh").await.unwrap();
        assert_eq!((a.get("gh").unwrap().as_str(), calls.load(Ordering::SeqCst)), ("ghp_wicket-test-refreshed", 2));
        let _ = std::fs::remove_dir_all(d);
    }

    /// #415: a secret set, rotated or removed after a run started reaches the run's node without a
    /// restart. Unset, the control host's refusal is held for the run (not asked per request) until
    /// the control host says it changed; then the next use takes the new state: set, rotated, gone.
    #[tokio::test]
    async fn a_secret_set_rotated_or_removed_after_start_follows_the_vault() {
        let d = tmp("follow");
        let v = Vault::new(d.join("vault"));
        let z = zone(
            "name: za\ninject: [{ host: api.github.com, header: authorization, format: 'Bearer {secret}', secret: gh, optional: true }]\n",
        );
        let now = Arc::new(AtomicI64::new(1_000));
        let clock: wicket_proxy::decide::Clock = {
            let now = now.clone();
            Arc::new(move || now.load(Ordering::SeqCst))
        };
        let (up, calls) = (Arc::new(AtomicI64::new(1)), Arc::new(AtomicU64::new(0)));
        let cache = Cache::new(clock);
        let a = Vault::from_source(cache.source(RA, fetcher(v.clone(), z, up, calls.clone())));
        // Not set: refused once, and that answer held for the run's next uses.
        for _ in 0..5 {
            assert!(a.ensure("gh").await.is_err());
            assert!(!a.has("gh"));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "a refusal isn't asked again per request");
        // Set: the control host says so (as a change), and the next use carries it.
        v.set("gh", VALUE).unwrap();
        v.set_hosts("gh", &["api.github.com".into()]).unwrap();
        cache.revoke(RA, "gh");
        a.ensure("gh").await.unwrap();
        assert_eq!(a.get_for("gh", "api.github.com").unwrap(), VALUE);
        // Rotated: dropped on the control host's word, and the new value fetched.
        v.set("gh", "ghp_wicket-test-rotated").unwrap();
        cache.revoke(RA, "gh");
        assert!(!a.has("gh"));
        a.ensure("gh").await.unwrap();
        assert_eq!(a.get_for("gh", "api.github.com").unwrap(), "ghp_wicket-test-rotated");
        // Removed: gone at once, and refused from then on.
        v.remove("gh").unwrap();
        cache.revoke(RA, "gh");
        assert!(!a.has("gh") && a.get("gh").is_err());
        assert!(a.ensure("gh").await.is_err());
        assert!(cache.names().is_empty());
        // A control host that never says: the refusal is asked about again once it is old.
        let asked = calls.load(Ordering::SeqCst);
        v.set("gh", VALUE).unwrap();
        v.set_hosts("gh", &["api.github.com".into()]).unwrap();
        assert!(a.ensure("gh").await.is_err(), "held");
        now.fetch_add(REFUSAL_HELD_MS, Ordering::SeqCst);
        a.ensure("gh").await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), asked + 1);
        // A run's refusals end with it.
        v.remove("gh").unwrap();
        cache.revoke(RA, "gh");
        assert!(a.ensure("gh").await.is_err());
        cache.release(RA);
        assert!(cache.refused.lock().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(d);
    }

    /// #415: a revoke for a run ends the uses shared from it with a child the node started (and that
    /// child's), not only the run's own; a child that fetched it for itself keeps it.
    #[test]
    fn a_revoke_ends_the_uses_shared_from_the_run() {
        let cache = Cache::new(Arc::new(|| 1_000));
        let f = Fetched { name: "gh".into(), value: VALUE.into(), hosts: vec!["h".into()], not_after: 5_000, upstream_expiry: None };
        cache.put(RA, &f);
        assert_eq!(cache.share(RA, RB, &["gh".into()], 5_000), ["gh"]);
        assert_eq!(cache.share(RB, "run_cccccccccccccccccccccccccc", &["gh".into()], 5_000), ["gh"]);
        cache.revoke(RA, "gh");
        assert!(cache.names().is_empty(), "the child's and grandchild's shared uses went with it");
        cache.put(RA, &f);
        cache.share(RA, RB, &["gh".into()], 5_000);
        cache.put(RB, &f);
        cache.revoke(RA, "gh");
        assert_eq!(cache.names(), ["gh"], "fetched for itself, the child keeps it");
        cache.revoke(RB, "gh");
        assert!(cache.names().is_empty());
    }

    /// #415: a revoke that arrives while a fetch is answered makes that answer stale: it isn't
    /// taken, and the secret is asked for again.
    #[tokio::test]
    async fn an_answer_a_revoke_overtook_is_not_taken() {
        let cache = Cache::new(Arc::new(|| 1_000));
        let calls = Arc::new(AtomicU64::new(0));
        let fetch: Fetcher = {
            let (cache, calls) = (cache.clone(), calls.clone());
            Arc::new(move |run, name| {
                let (cache, calls) = (cache.clone(), calls.clone());
                Box::pin(async move {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    // The first answer is overtaken by a revoke (the value changed meanwhile).
                    if n == 0 {
                        cache.revoke(&run, &name);
                    }
                    Ok(Fetched { name, value: format!("v{n}"), hosts: vec!["h".into()], not_after: 5_000, upstream_expiry: None })
                })
            })
        };
        let a = Vault::from_source(cache.source(RA, fetch));
        a.ensure("gh").await.unwrap();
        assert_eq!((a.get("gh").unwrap().as_str(), calls.load(Ordering::SeqCst)), ("v1", 2), "the stale answer was dropped");
    }

    fn grep_tree(d: &Path, needle: &str) -> bool {
        let Ok(rd) = std::fs::read_dir(d) else { return false };
        rd.flatten().any(|e| {
            let p = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => grep_tree(&p, needle),
                Ok(t) if t.is_file() => std::fs::read(&p).is_ok_and(|b| b.windows(needle.len()).any(|w| w == needle.as_bytes())),
                _ => false,
            }
        })
    }

    #[tokio::test]
    async fn a_use_ends_with_the_runs_authority_or_the_upstream_expiry() {
        let now = Arc::new(AtomicI64::new(1_000));
        let clock: wicket_proxy::decide::Clock = {
            let now = now.clone();
            Arc::new(move || now.load(Ordering::SeqCst))
        };
        let cache = Cache::new(clock);
        let f = Fetched { name: "m".into(), value: "tok".into(), hosts: vec!["h".into()], not_after: 5_000, upstream_expiry: Some(9_000) };
        cache.put(RA, &f);
        let mut g = f.clone();
        g.not_after = 20_000;
        cache.put(RB, &g);
        let fail: Fetcher = Arc::new(|_, _| Box::pin(async { Err(Unfetched::Unreachable("unreachable".into())) }));
        let a = Vault::from_source(cache.source(RA, fail.clone()));
        let b = Vault::from_source(cache.source(RB, fail));
        assert!(a.has("m") && b.has("m"));
        now.store(5_000, Ordering::SeqCst);
        assert!(!a.has("m") && b.has("m"), "run a's authority has ended");
        now.store(9_000, Ordering::SeqCst);
        assert!(!b.has("m"), "the upstream token has expired");
        cache.sweep();
        assert!(cache.names().is_empty());
    }

    /// #162: across a re-exec the cache moves through a sealed memfd, never a file.
    #[test]
    fn the_cache_hands_over_through_a_sealed_memfd() {
        let cache = Cache::new(Arc::new(|| 1_000));
        cache.put(RA, &Fetched { name: "m".into(), value: VALUE.into(), hosts: vec!["h".into()], not_after: 5_000, upstream_expiry: None });
        let fd = cache.export().unwrap();
        let link = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap();
        assert!(link.to_string_lossy().starts_with("/memfd:wicket-node-secrets"), "{}", link.display());
        // Sealed: it can't be written to or grown.
        let mut f = std::fs::File::from(fd.try_clone().unwrap());
        assert!(std::io::Write::write_all(&mut f, b"x").is_err());
        // SAFETY: fcntl on our own fd.
        assert_eq!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC, 0, "inherited by the exec");
        let next = Cache::new(Arc::new(|| 1_000));
        assert_eq!(next.import(fd).unwrap(), 1);
        let v = Vault::from_source(next.source(RA, Arc::new(|_, _| Box::pin(async { Err(Unfetched::Unreachable("no".into())) }))));
        assert_eq!(v.get_for("m", "h").unwrap(), VALUE);
        // Anything but a sealed memfd is refused.
        let plain = std::fs::File::open("/dev/null").unwrap();
        assert!(Cache::new(Arc::new(|| 0)).import(OwnedFd::from(plain)).is_err());
    }

    #[test]
    fn asks_queue_once_per_op_and_survive_a_restart() {
        let d = tmp("asks");
        let op = wicket_core::Op::egress(&wicket_core::TenantId::single(), &wicket_core::RunId(RA.into()), "z", "GET", "x.example", "/a");
        let a = Asks::open(&d);
        let (id, new) = a.push(RA, &op, "out of reach", None, 5, false);
        assert!(new);
        assert_eq!(a.push(RA, &op, "out of reach", None, 9, false), (id.clone(), false), "deduplicated");
        let a = Asks::open(&d);
        assert_eq!(a.of(RA).len(), 1);
        assert_eq!(a.of(RA)[0].at, 5, "keeps its original time");
        a.remove(&id);
        assert!(Asks::open(&d).of(RA).is_empty());
        let _ = std::fs::remove_dir_all(d);
    }
}
