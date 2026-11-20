//! The PoC vault: one file per secret under `~/.config/wicket/secrets`, mode 0600. Secrets are read
//! only by the enforcement points and never written into a sandbox, a log or the audit chain.
//!
//! A secret can also be a **reference** (`<name>.ref`): a file plus a JSON pointer, re-read on every
//! use. That is how wicket uses a login another program on the host keeps (a harness's own): it
//! reads the current access token at request time and never touches the refresh token or writes the
//! file, so that program keeps refreshing its own login.
//!
//! **Each secret is bound to the hosts it may be sent to** (`<name>.hosts`, written by whoever stores
//! it: root, on a system install). The egress proxy, credential swaps and the model proxy send a
//! secret only to those hosts, whatever a manifest asks; a secret with no hosts is sent nowhere. The
//! vault has no defaults of its own: `wicket secret set` and `link` bind a harness's default model
//! secret to its model host, as its adapter says, when they store it with no binding.

use anyhow::{bail, Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Clone)]
pub struct Vault {
    dir: PathBuf,
    /// Instead of the directory: secrets held elsewhere, e.g. sealed to a node (#152).
    source: Option<std::sync::Arc<dyn SecretSource>>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault").field("dir", &self.dir).field("sealed", &self.source.is_some()).finish()
    }
}

/// Where a vault reads secrets other than its own directory: a node's in-memory cache of the secrets
/// its runs have used (#152). Bindings travel with each secret and are enforced the same way.
pub trait SecretSource: Send + Sync {
    /// The secret's current value, if held and not expired.
    fn get(&self, name: &str) -> Result<String>;
    /// The hosts it may be sent to.
    fn hosts(&self, name: &str) -> Vec<String>;
    /// Whether it is held (and not expired).
    fn has(&self, name: &str) -> bool;
    /// Makes `name` available if it isn't: a node fetches it from its control host on first use.
    fn fetch<'a>(&'a self, _name: &'a str) -> futures_util::future::BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
    /// Reads `name` again from where it comes from, even if held: the upstream refused the value
    /// held (#360), so a node asks its control host for the current one. By default, as [`fetch`].
    ///
    /// [`fetch`]: SecretSource::fetch
    fn refetch<'a>(&'a self, name: &'a str) -> futures_util::future::BoxFuture<'a, Result<()>> {
        self.fetch(name)
    }
}

impl Vault {
    pub fn new(dir: PathBuf) -> Vault {
        Vault { dir, source: None }
    }

    /// Makes `name` available before use: a source fetches it if it doesn't hold it (#152). A
    /// directory vault has nothing to fetch.
    pub async fn ensure(&self, name: &str) -> Result<()> {
        match &self.source {
            Some(s) if !s.has(name) => s.fetch(name).await,
            _ => Ok(()),
        }
    }

    /// Re-reads `name` from its source after an upstream refused the value read (#360): a node's
    /// cache asks the control host for the current value. A directory vault reads its files (and a
    /// link's file) at every use, so it has nothing to do.
    pub async fn refetch(&self, name: &str) -> Result<()> {
        match &self.source {
            Some(s) => s.refetch(name).await,
            None => Ok(()),
        }
    }

    /// Whether this vault's secrets come from a source (a node's cache) rather than a directory.
    pub fn is_sourced(&self) -> bool {
        self.source.is_some()
    }

    /// A vault whose secrets come from `source` only (a node's cache, #152).
    pub fn from_source(source: std::sync::Arc<dyn SecretSource>) -> Vault {
        Vault { dir: PathBuf::from("/nonexistent/wicket-sealed-vault"), source: Some(source) }
    }

    /// When a reference's current value expires upstream (Unix ms), if its file says so (e.g. the
    /// linked login's access token): a node holding a copy drops it then (#152).
    pub fn expires_at(&self, name: &str) -> Option<i64> {
        let spec = self.read_ref(name).ok()?;
        if let Some(h) = &spec.helper {
            return h.fetch(name).ok()?.expires_at;
        }
        let (file, ep) = (spec.file?, spec.expires_pointer?);
        let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(file).ok()?).ok()?;
        doc.pointer(&ep)?.as_i64()
    }

    pub fn default_dir() -> PathBuf {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
        home.join(".config/wicket/secrets")
    }

    fn path(&self, name: &str) -> Result<PathBuf> {
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            bail!("invalid secret name {name:?}");
        }
        Ok(self.dir.join(name))
    }

    pub fn get(&self, name: &str) -> Result<String> {
        if let Some(s) = &self.source {
            return s.get(name);
        }
        let p = self.path(name)?;
        if p.with_extension("ref").exists() {
            return self.get_ref(name);
        }
        let meta = std::fs::metadata(&p).with_context(|| format!("secret {name:?} is not set (run: wicket secret set {name})"))?;
        if let Err(why) = check_private(&p, &meta) {
            bail!("secret file {} must not be readable by group or others: {why}", p.display());
        }
        let v = std::fs::read_to_string(&p)?;
        let v = v.trim().to_string();
        if v.is_empty() {
            bail!("secret {name:?} is empty");
        }
        Ok(v)
    }

    fn get_ref(&self, name: &str) -> Result<String> {
        let spec = self.read_ref(name)?;
        if let Some(h) = &spec.helper {
            return Ok(h.fetch(name)?.value);
        }
        let file = spec.file.as_deref().with_context(|| format!("{name}.ref needs \"file\""))?;
        // No pointer: the whole file is the secret (e.g. an API key file).
        read_linked(name, file, spec.pointer.as_deref(), spec.expires_pointer.as_deref())
            .map(|(v, _)| v)
            .map_err(|e| unreadable_hint(name, file, e))
    }

    /// `name`'s link (`<name>.ref`), as written by [`Vault::link`] or [`Vault::link_via_helper`].
    fn read_ref(&self, name: &str) -> Result<RefFile> {
        let r = self.path(name)?.with_extension("ref");
        serde_json::from_str(&std::fs::read_to_string(&r)?).with_context(|| format!("{name}.ref is malformed"))
    }

    /// Writes `name`'s link (private, in a private directory) in place of any stored value, and
    /// checks it by reading the secret through it once.
    fn write_ref(&self, name: &str, spec: &RefFile) -> Result<()> {
        let p = self.path(name)?;
        std::fs::create_dir_all(&self.dir)?;
        std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        let r = p.with_extension("ref");
        std::fs::write(&r, serde_json::to_vec_pretty(spec)?)?;
        std::fs::set_permissions(&r, std::fs::Permissions::from_mode(0o600))?;
        let _ = std::fs::remove_file(&p);
        self.get(name).map(|_| ())
    }

    /// For a secret linked to a JSON field, the object that holds it, as the file has it now (e.g.
    /// a harness login's object, for its non-secret fields: scopes, plan).
    /// None for a stored secret or a whole-file link.
    pub fn linked_object(&self, name: &str) -> Option<serde_json::Value> {
        let spec = self.read_ref(name).ok()?;
        let (file, pointer) = (spec.file?, spec.pointer?);
        let parent = &pointer[..pointer.rfind('/')?];
        let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(file).ok()?).ok()?;
        doc.pointer(parent).filter(|v| v.is_object()).cloned()
    }

    /// What the linker stored with a linked secret (see [`Vault::link`]); None for a stored secret,
    /// or a link made without any.
    pub fn link_meta(&self, name: &str) -> Option<serde_json::Value> {
        self.read_ref(name).ok()?.meta
    }

    /// Makes `name` a reference to another file (never copied into the vault): a JSON field in it,
    /// or with no `pointer`, the whole file, trimmed. `meta` is kept with the reference as it is,
    /// replacing what an earlier link kept: opaque to the vault, never a credential (e.g. the
    /// account fields a harness reads from the login's config once, at link time, #298).
    pub fn link(
        &self,
        name: &str,
        file: &str,
        pointer: Option<&str>,
        expires_pointer: Option<&str>,
        meta: Option<&serde_json::Value>,
    ) -> Result<()> {
        if pointer.is_none() && expires_pointer.is_some() {
            bail!("an expiry pointer needs a JSON pointer: a whole-file reference has no fields");
        }
        let spec = RefFile {
            file: Some(file.into()),
            pointer: pointer.map(String::from),
            expires_pointer: expires_pointer.map(String::from),
            helper: None,
            meta: meta.cloned(),
        };
        self.write_ref(name, &spec)
    }

    /// Makes `name` a reference to a value `wicket secret serve` holds, running as the linked file's
    /// owner (#350): wicket never reads the file, and the helper answers only with the value it was
    /// told to serve under this name and its expiry. `file` is only noted, for people reading the
    /// link. Checked by fetching the value once, as for [`Vault::link`].
    pub fn link_via_helper(
        &self,
        name: &str,
        helper: &crate::secret_helper::HelperRef,
        file: Option<&str>,
        meta: Option<&serde_json::Value>,
    ) -> Result<()> {
        let spec = RefFile {
            file: file.map(String::from),
            pointer: None,
            expires_pointer: None,
            helper: Some(helper.clone()),
            meta: meta.cloned(),
        };
        self.write_ref(name, &spec)
    }

    /// The helper a linked secret is read through (#350), if it is linked that way.
    pub fn helper_of(&self, name: &str) -> Option<crate::secret_helper::HelperRef> {
        self.read_ref(name).ok()?.helper
    }

    /// [`Vault::get_for`], for a request about to go upstream (#350): a value that can't be read is
    /// read again for up to `patience` (a linked login's owner may be rewriting its file, or its
    /// helper restarting), and an error then names the secret and the cause. A host the secret
    /// isn't bound to is refused at once.
    pub async fn get_for_patiently(&self, name: &str, host: &str, patience: std::time::Duration) -> Result<String> {
        self.check(name, host)?;
        let until = tokio::time::Instant::now() + patience;
        let mut tries = 0u32;
        loop {
            tries += 1;
            match self.get(name) {
                Ok(v) => return Ok(v),
                Err(e) if tokio::time::Instant::now() >= until => {
                    return Err(SecretUnavailable { name: name.to_string(), tries, cause: format!("{e:#}") }.into());
                }
                Err(_) => tokio::time::sleep(RETRY_STEP.min(patience)).await,
            }
        }
    }

    /// The hosts `name` may be sent to: its `.hosts` list, else none.
    pub fn hosts(&self, name: &str) -> Vec<String> {
        if let Some(s) = &self.source {
            return s.hosts(name);
        }
        let Ok(p) = self.path(name) else { return vec![] };
        match std::fs::read(p.with_extension("hosts")) {
            Ok(b) => serde_json::from_slice::<Vec<String>>(&b).unwrap_or_default(),
            Err(_) => vec![],
        }
    }

    /// Binds `name` to exactly these hosts (patterns: `api.example.com`, `*.example.com`). Refused
    /// for a `verify` secret (#578): it is sent nowhere, whatever binding is asked for.
    pub fn set_hosts(&self, name: &str, hosts: &[String]) -> Result<()> {
        let p = self.path(name)?;
        let v = normalize_hosts(hosts)?;
        if !v.is_empty() && self.is_verify(name) {
            bail!(
                "secret {name:?} verifies trigger deliveries, so it is sent nowhere: give it no hosts (or store another secret for egress)"
            );
        }
        std::fs::create_dir_all(&self.dir)?;
        std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        let f = p.with_extension("hosts");
        let tmp = p.with_extension("hosts-tmp");
        std::fs::write(&tmp, serde_json::to_vec(&v)?)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp, &f)?;
        Ok(())
    }

    /// Whether `name` is a `verify` secret (#578): used only to check the signatures of a trigger's
    /// webhook deliveries (`<name>.verify`). It is bound to no host, so no injection, credential
    /// swap or model proxy can read it (`get_for` refuses a secret with no hosts).
    pub fn is_verify(&self, name: &str) -> bool {
        if self.source.is_some() {
            return false;
        }
        self.path(name).map(|p| p.with_extension("verify").exists()).unwrap_or(false)
    }

    /// Makes `name` a `verify` secret ([`Vault::is_verify`]). Refused while it is bound to hosts:
    /// one secret either goes to hosts or checks deliveries, never both.
    pub fn set_verify(&self, name: &str) -> Result<()> {
        let p = self.path(name)?;
        if !self.has(name) {
            bail!("no secret {name:?} (wicket secret set {name})");
        }
        let hosts = self.hosts(name);
        if !hosts.is_empty() {
            bail!(
                "secret {name:?} may be sent to {}: a verify secret is sent nowhere, so store the webhook's key as a secret of its own",
                hosts.join(", ")
            );
        }
        let f = p.with_extension("verify");
        std::fs::write(&f, b"verify\n")?;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    /// A `verify` secret's value, for checking a delivery's signature: refused for any other secret.
    pub fn get_verify(&self, name: &str) -> Result<String> {
        if !self.is_verify(name) {
            bail!("secret {name:?} isn't a verify secret (as root: wicket secret verify {name})");
        }
        self.get(name)
    }

    /// Whether `name` may be sent to `host` (a host name, or a `*.` pattern: then every host it
    /// matches must be allowed).
    pub fn allows(&self, name: &str, host: &str) -> bool {
        self.hosts(name).iter().any(|a| covers(a, host))
    }

    /// Ok if `name` may be sent to `host`, else why not.
    pub fn check(&self, name: &str, host: &str) -> Result<()> {
        if self.allows(name, host) {
            return Ok(());
        }
        let hosts = self.hosts(name);
        if hosts.is_empty() {
            bail!("secret {name:?} is bound to no hosts, so it is sent nowhere (as root: wicket secret hosts {name} --hosts HOST[,HOST])");
        }
        bail!("secret {name:?} may be sent only to {}, not to {host}", hosts.join(", "))
    }

    /// The secret, if it may be sent to `host`: what every enforcement point uses.
    pub fn get_for(&self, name: &str, host: &str) -> Result<String> {
        self.check(name, host)?;
        self.get(name)
    }

    pub fn has(&self, name: &str) -> bool {
        if let Some(s) = &self.source {
            return s.has(name);
        }
        self.path(name).map(|p| p.exists() || p.with_extension("ref").exists()).unwrap_or(false)
    }

    pub fn set(&self, name: &str, value: &str) -> Result<()> {
        let p = self.path(name)?;
        std::fs::create_dir_all(&self.dir)?;
        std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, value.trim())?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp, &p)?;
        Ok(())
    }

    /// Removes `name` (its value or reference, and its host binding).
    pub fn remove(&self, name: &str) -> Result<()> {
        let p = self.path(name)?;
        for f in [p.clone(), p.with_extension("ref"), p.with_extension("hosts"), p.with_extension("verify")] {
            match std::fs::remove_file(&f) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            }
        }
        Ok(())
    }

    /// What the vault knows about `name` besides its value (never read here): whether it is a stored
    /// value or a reference (and what it refers to), its hosts, and when it was last set (the value's
    /// or reference's file time). None if it isn't in this vault's directory.
    pub fn info(&self, name: &str) -> Option<SecretInfo> {
        let p = self.path(name).ok()?;
        let r = p.with_extension("ref");
        let (reference, meta) = match std::fs::symlink_metadata(&r) {
            Ok(m) => {
                let spec = self.read_ref(name).unwrap_or_default();
                (Some(Reference { file: spec.file.unwrap_or_default(), pointer: spec.pointer }), m)
            }
            Err(_) => (None, std::fs::symlink_metadata(&p).ok()?),
        };
        let set_at = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64);
        Some(SecretInfo { name: name.to_string(), reference, hosts: self.hosts(name), set_at })
    }

    /// The names of the secrets in this vault's directory, sorted.
    pub fn names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.list().into_iter().map(|n| n.strip_suffix(" (reference)").map(String::from).unwrap_or(n)).collect();
        v.retain(|n| self.path(n).is_ok());
        v.dedup();
        v
    }

    pub fn list(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| !n.ends_with(".tmp") && !n.ends_with(".hosts") && !n.ends_with(".hosts-tmp") && !n.ends_with(".verify"))
                    .map(|n| match n.strip_suffix(".ref") {
                        Some(b) => format!("{b} (reference)"),
                        None => n,
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
}

/// A linked secret's `<name>.ref`: what it refers to, never the value. A file (its JSON field at
/// `pointer`, or all of it), with where its expiry is; or a helper that serves it (#350). `meta` is
/// the linker's, opaque here. Read leniently (a `null` is an absent field), so links any build wrote
/// read alike.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
struct RefFile {
    #[serde(default)]
    file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pointer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_pointer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    helper: Option<crate::secret_helper::HelperRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    meta: Option<serde_json::Value>,
}

/// A link file's text as [`Vault`] reads it (`read_ref`), written back as it writes one
/// (`write_ref`): None if it doesn't read. For the fuzz target (#326), whose oracle is that what
/// reads writes as what reads back the same.
#[doc(hidden)]
pub fn ref_file_round_trip(text: &str) -> Option<String> {
    let r: RefFile = serde_json::from_str(text).ok()?;
    Some(String::from_utf8(serde_json::to_vec_pretty(&r).ok()?).expect("JSON is UTF-8"))
}

/// A secret as [`Vault::info`] describes it: never its value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretInfo {
    pub name: String,
    /// Set for a reference (`wicket secret link`): what it refers to.
    pub reference: Option<Reference>,
    pub hosts: Vec<String>,
    /// When its value or reference was last written (Unix seconds).
    pub set_at: Option<i64>,
}

/// What a reference names: a file on the host and, for a JSON field in it, a pointer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    pub file: String,
    pub pointer: Option<String>,
}

/// Host patterns as a binding keeps them: trimmed, lowercased, without a trailing dot, each checked
/// (as [`Vault::set_hosts`] does), duplicates dropped.
pub fn normalize_hosts(hosts: &[String]) -> Result<Vec<String>> {
    let mut v = Vec::new();
    for h in hosts {
        let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
        check_host_pattern(&h)?;
        if !v.contains(&h) {
            v.push(h);
        }
    }
    Ok(v)
}

/// How often [`Vault::get_for_patiently`] tries again.
const RETRY_STEP: std::time::Duration = std::time::Duration::from_millis(200);

/// A secret that still couldn't be read after [`Vault::get_for_patiently`]'s retries: which one,
/// and why (never its value).
#[derive(Debug)]
pub struct SecretUnavailable {
    pub name: String,
    pub tries: u32,
    pub cause: String,
}

impl std::fmt::Display for SecretUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.tries;
        write!(f, "secret {:?} could not be read ({n} tr{}): {}", self.name, if n == 1 { "y" } else { "ies" }, self.cause)
    }
}

impl std::error::Error for SecretUnavailable {}

/// A host name or IP address, or `*.` and a name with at least two labels.
fn check_host_pattern(h: &str) -> Result<()> {
    let name = h.strip_prefix("*.").unwrap_or(h);
    let ok_chars = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    let ok_labels = name.split('.').all(|l| !l.is_empty() && !l.starts_with('-') && !l.ends_with('-'));
    if !ok_chars || !ok_labels || (h.starts_with("*.") && !name.contains('.')) {
        bail!("{h:?} is not a host name, or *. and a domain with at least two labels");
    }
    Ok(())
}

/// Whether the allowed pattern `allowed` covers `wanted` (a host, or a `*.` pattern).
pub fn covers(allowed: &str, wanted: &str) -> bool {
    let wanted = wanted.trim_end_matches('.').to_ascii_lowercase();
    match (allowed.strip_prefix("*."), wanted.strip_prefix("*.")) {
        (Some(a), Some(w)) => w == a || w.ends_with(&format!(".{a}")),
        (None, Some(_)) => false,
        _ => wicket_core::manifest::host_matches(allowed, &wanted),
    }
}

/// The current value of a secret linked to `file` (a JSON field in it, or with no `pointer`, the whole
/// file, trimmed), and when it expires (Unix ms) if `expires_pointer` says. Refused if anyone but its
/// owner and this process's user can read the file, or the value has expired. What the vault reads for
/// a link, and what `wicket secret serve` reads, as the file's owner, for a link via the helper (#350).
pub fn read_linked(name: &str, file: &str, pointer: Option<&str>, expires_pointer: Option<&str>) -> Result<(String, Option<i64>)> {
    if pointer.is_none() && expires_pointer.is_some() {
        bail!("an expiry pointer needs a JSON pointer: a whole-file reference has no fields");
    }
    let meta = std::fs::metadata(file).with_context(|| format!("secret {name} refers to {file}, which is missing or can't be reached"))?;
    if let Err(why) = check_private(std::path::Path::new(file), &meta) {
        bail!("{file} (referenced by secret {name}) must not be readable by group or others: {why}");
    }
    let text = std::fs::read_to_string(file).with_context(|| format!("secret {name}: reading {file}"))?;
    let Some(pointer) = pointer else {
        if text.trim().is_empty() {
            bail!("secret {name} is empty");
        }
        return Ok((text.trim().to_string(), None));
    };
    let doc: serde_json::Value = serde_json::from_str(&text).with_context(|| format!("secret {name}: {file} is not JSON"))?;
    let expires = expires_pointer.and_then(|ep| doc.pointer(ep)).and_then(|v| v.as_i64());
    if let Some(ms) = expires {
        if ms <= now_ms() {
            bail!("secret {name}: the referenced token has expired; its owner (the program on the host whose login it is) must refresh it");
        }
    }
    let v = doc.pointer(pointer).and_then(|v| v.as_str()).with_context(|| format!("secret {name}: nothing at {pointer} in {file}"))?;
    if v.trim().is_empty() {
        bail!("secret {name} is empty");
    }
    Ok((v.trim().to_string(), expires))
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// A linked file wicket may not read: says how to link it without an ACL (#350).
fn unreadable_hint(name: &str, file: &str, e: anyhow::Error) -> anyhow::Error {
    let denied = e.chain().any(|c| c.downcast_ref::<std::io::Error>().is_some_and(|io| io.kind() == std::io::ErrorKind::PermissionDenied));
    if !denied {
        return e;
    }
    e.context(format!(
        "wicket can't read {file}, which secret {name} is linked to: run `wicket secret serve` as the file's owner and link it with \
         --via-helper (docs/how-to/store-and-link-secrets.md), rather than sharing the file by an ACL"
    ))
}

/// Refuses a secret file that anyone but its owner (and the user wicket runs as) can read. A mode
/// with no group or other bits passes. Otherwise the file's POSIX access ACL decides: a file shared
/// read-only with exactly the wicket user (`setfacl -m u:wicket:r FILE`) shows the ACL mask in its
/// group bits, and passes as long as no one else is granted read. On refusal, says who can read it.
fn check_private(path: &std::path::Path, meta: &std::fs::Metadata) -> std::result::Result<(), String> {
    let mode = meta.permissions().mode();
    if mode & 0o077 == 0 {
        return Ok(());
    }
    let refuse_mode = || {
        let mut who = Vec::new();
        if mode & 0o070 != 0 {
            who.push("its group");
        }
        if mode & 0o007 != 0 {
            who.push("others");
        }
        Err(format!("its mode {:03o} gives {} access", mode & 0o777, who.join(" and ")))
    };
    let Some(raw) = access_acl(path) else { return refuse_mode() };
    let acl = parse_acl(&raw).map_err(|e| format!("its ACL can't be read ({e})"))?;
    if !acl.iter().any(|e| matches!(e.tag, AclTag::User | AclTag::Group | AclTag::Mask)) {
        // A minimal ACL is just the mode.
        return refuse_mode();
    }
    let readers = acl_readers(&acl, unsafe { libc::geteuid() });
    if readers.is_empty() {
        Ok(())
    } else {
        Err(format!("its ACL lets {} read it", readers.join(", ")))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclTag {
    UserObj,
    User,
    GroupObj,
    Group,
    Mask,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AclEntry {
    tag: AclTag,
    perm: u16,
    id: u32,
}

const ACL_READ: u16 = 4;

/// The raw `system.posix_acl_access` xattr, or None when the file has none or the filesystem
/// doesn't support it.
fn access_acl(path: &std::path::Path) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let p = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let name = c"system.posix_acl_access";
    for _ in 0..4 {
        // SAFETY: valid NUL-terminated strings; a null buffer of size 0 asks for the size.
        let n = unsafe { libc::getxattr(p.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if n <= 0 {
            return None;
        }
        let mut buf = vec![0u8; n as usize];
        // SAFETY: buf is writable for buf.len() bytes.
        let m = unsafe { libc::getxattr(p.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
        if m >= 0 {
            buf.truncate(m as usize);
            return Some(buf);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ERANGE) {
            return None;
        }
        // It grew between the calls: ask again.
    }
    None
}

/// Parses the Linux POSIX ACL xattr: a little-endian u32 version (2), then 8-byte entries of
/// u16 tag, u16 permissions (r=4, w=2, x=1) and u32 id (for named users and groups).
fn parse_acl(raw: &[u8]) -> Result<Vec<AclEntry>> {
    if raw.len() < 4 || !(raw.len() - 4).is_multiple_of(8) {
        bail!("{} bytes is not a POSIX ACL", raw.len());
    }
    let version = u32::from_le_bytes(raw[..4].try_into().unwrap());
    if version != 2 {
        bail!("ACL version {version}, not 2");
    }
    raw[4..]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| {
            let tag = match u16::from_le_bytes([c[0], c[1]]) {
                0x01 => AclTag::UserObj,
                0x02 => AclTag::User,
                0x04 => AclTag::GroupObj,
                0x08 => AclTag::Group,
                0x10 => AclTag::Mask,
                0x20 => AclTag::Other,
                t => bail!("unknown ACL tag {t:#x}"),
            };
            Ok(AclEntry { tag, perm: u16::from_le_bytes([c[2], c[3]]), id: u32::from_le_bytes([c[4], c[5], c[6], c[7]]) })
        })
        .collect()
}

/// Who, besides the owner and `me`, the ACL lets read the file. Named users, named groups and the
/// owning group are limited by the mask when there is one; others are not.
fn acl_readers(acl: &[AclEntry], me: u32) -> Vec<String> {
    let mask = acl.iter().find(|e| e.tag == AclTag::Mask).map_or(u16::MAX, |e| e.perm);
    let reads = |e: &AclEntry, masked: bool| e.perm & ACL_READ != 0 && (!masked || mask & ACL_READ != 0);
    let mut who = Vec::new();
    for e in acl {
        match e.tag {
            AclTag::User if e.id != me && reads(e, true) => who.push(format!("user {}", e.id)),
            AclTag::GroupObj if reads(e, true) => who.push("its group".to_string()),
            AclTag::Group if reads(e, true) => who.push(format!("group {}", e.id)),
            AclTag::Other if reads(e, false) => who.push("others".to_string()),
            _ => {}
        }
    }
    who
}

#[cfg(test)]
mod tests {
    /// #578 step 4: a `verify` secret is sent nowhere. It can't have hosts, a secret with hosts
    /// can't become one, egress can't read it, and only `get_verify` gives its value.
    #[test]
    fn a_verify_secret_is_sent_nowhere() {
        let dir = std::env::temp_dir().join(format!("wicket-vault-verify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let v = super::Vault::new(dir.clone());
        v.set("hook", "k3y").unwrap();
        v.set("gh", "t0k").unwrap();
        v.set_hosts("gh", &["api.github.com".into()]).unwrap();
        assert!(v.get_verify("hook").is_err(), "not yet a verify secret");
        v.set_verify("hook").unwrap();
        assert!(v.is_verify("hook"));
        assert_eq!(v.get_verify("hook").unwrap(), "k3y");
        assert!(v.get_for("hook", "api.github.com").is_err(), "egress never reads it");
        assert!(v.set_hosts("hook", &["api.github.com".into()]).unwrap_err().to_string().contains("sent nowhere"));
        assert!(v.set_verify("gh").unwrap_err().to_string().contains("api.github.com"), "a secret with hosts can't be one");
        assert!(v.set_verify("missing").is_err());
        assert_eq!(v.names(), ["gh", "hook"], "the binding isn't listed as a secret");
        v.remove("hook").unwrap();
        assert!(!v.is_verify("hook"), "removed with its secret");
        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;

    #[test]
    fn secrets_go_only_to_the_hosts_they_are_bound_to() {
        let dir = std::env::temp_dir().join(format!("wicket-vault-hosts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let v = Vault::new(dir.clone());
        v.set("gh", "tok").unwrap();
        assert!(v.get_for("gh", "api.github.com").unwrap_err().to_string().contains("bound to no hosts"), "unbound: nowhere");
        v.set_hosts("gh", &["API.github.com.".into(), "*.githubusercontent.com".into()]).unwrap();
        assert_eq!(v.hosts("gh"), ["api.github.com", "*.githubusercontent.com"]);
        assert_eq!(v.get_for("gh", "api.github.com").unwrap(), "tok");
        assert_eq!(v.get_for("gh", "raw.githubusercontent.com").unwrap(), "tok");
        assert!(v.allows("gh", "*.githubusercontent.com") && v.allows("gh", "*.a.githubusercontent.com"));
        for bad in ["attacker.example", "github.com", "githubusercontent.com", "*.github.com", "api.github.com.attacker.example"] {
            assert!(v.get_for("gh", bad).is_err(), "{bad}");
        }
        assert_eq!(v.list(), ["gh"], "the binding isn't a secret of its own");
        // No name has a default of its own: a model login is as unbound as any other secret.
        v.set("model-login", "t").unwrap();
        assert!(v.hosts("model-login").is_empty() && !v.allows("model-login", "models.example"));
        v.set_hosts("model-login", &["127.0.0.1".into()]).unwrap();
        assert!(!v.allows("model-login", "models.example") && v.allows("model-login", "127.0.0.1"));
        for bad in ["*", "*.com", "a/b", "", "-a.com", "a..com", "*.*.com"] {
            assert!(v.set_hosts("gh", &[bad.into()]).is_err(), "{bad:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn info_says_what_a_secret_is_and_never_its_value() {
        let dir = std::env::temp_dir().join(format!("wicket-vault-info-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let v = Vault::new(dir.join("vault"));
        assert!(v.info("gh").is_none() && v.names().is_empty());
        v.set("gh", "tok-very-secret").unwrap();
        v.set_hosts("gh", &["api.github.com".into()]).unwrap();
        let key = dir.join("key");
        std::fs::write(&key, "k").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        v.link("api", key.to_str().unwrap(), None, None, None).unwrap();
        assert_eq!(v.names(), ["api", "gh"]);
        let gh = v.info("gh").unwrap();
        assert!(gh.reference.is_none() && gh.hosts == ["api.github.com"] && gh.set_at.is_some());
        assert!(!format!("{gh:?}").contains("tok-"), "no value in it");
        let api = v.info("api").unwrap();
        assert_eq!(api.reference, Some(Reference { file: key.to_str().unwrap().into(), pointer: None }));
        assert!(api.hosts.is_empty());
        assert_eq!(normalize_hosts(&["A.example.".into(), "a.example".into()]).unwrap(), ["a.example"]);
        assert!(normalize_hosts(&["*".into()]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn references_read_the_current_value_and_respect_expiry() {
        let dir = std::env::temp_dir().join(format!("wicket-vault-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let creds = dir.join("creds.json");
        let write = |tok: &str, exp: i64| {
            std::fs::write(&creds, format!(r#"{{"o":{{"accessToken":"{tok}","refreshToken":"never-read","expiresAt":{exp}}}}}"#)).unwrap();
            std::fs::set_permissions(&creds, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        let far = 32503680000000i64; // year 3000, in ms
        write("tok-1", far);
        let v = Vault::new(dir.join("vault"));
        v.link("login", creds.to_str().unwrap(), Some("/o/accessToken"), Some("/o/expiresAt"), None).unwrap();
        assert_eq!(v.get("login").unwrap(), "tok-1");
        write("tok-2", far); // the owner refreshed it: we see the new value
        assert_eq!(v.get("login").unwrap(), "tok-2");
        write("tok-3", 1000); // expired
        assert!(v.get("login").unwrap_err().to_string().contains("expired"));
        std::fs::set_permissions(&creds, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(v.get("login").is_err(), "world-readable source refused");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_link_keeps_its_metadata_until_relinked() {
        let dir = std::env::temp_dir().join(format!("wicket-vault-meta-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("api-key");
        std::fs::write(&key, "key-1\n").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let v = Vault::new(dir.join("vault"));
        v.link("api", key.to_str().unwrap(), None, None, Some(&serde_json::json!({ "a": 1 }))).unwrap();
        assert_eq!(v.link_meta("api").unwrap()["a"], 1);
        v.link("api", key.to_str().unwrap(), None, None, None).unwrap();
        assert_eq!(v.link_meta("api"), None, "a re-link replaces what the last one kept");
        v.set("stored", "x").unwrap();
        assert_eq!(v.link_meta("stored"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Links as earlier builds wrote them (every field present, `null` for none) read as they did.
    #[test]
    fn links_written_by_earlier_builds_still_read() {
        let dir = std::env::temp_dir().join(format!("wicket-vault-oldref-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("vault")).unwrap();
        let login = dir.join("login.json");
        std::fs::write(&login, r#"{"acct": {"token": "tok-1", "expires": 4102444800000, "plan": "max"}}"#).unwrap();
        std::fs::set_permissions(&login, std::fs::Permissions::from_mode(0o600)).unwrap();
        let v = Vault::new(dir.join("vault"));
        let old = serde_json::json!({ "file": login, "pointer": "/acct/token", "expires_pointer": "/acct/expires", "meta": null });
        std::fs::write(dir.join("vault/claude.ref"), serde_json::to_vec_pretty(&old).unwrap()).unwrap();
        assert_eq!(v.get("claude").unwrap(), "tok-1");
        assert_eq!(v.expires_at("claude"), Some(4_102_444_800_000));
        assert_eq!(v.linked_object("claude").unwrap()["plan"], "max");
        assert_eq!((v.link_meta("claude"), v.helper_of("claude")), (None, None));
        assert_eq!(v.info("claude").unwrap().reference.unwrap().pointer.as_deref(), Some("/acct/token"));
        // A whole-file link: no pointer at all, and `null` for the expiry.
        let key = dir.join("key");
        std::fs::write(&key, "k\n").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let old = serde_json::json!({ "file": key, "pointer": null, "expires_pointer": null });
        std::fs::write(dir.join("vault/api.ref"), serde_json::to_vec_pretty(&old).unwrap()).unwrap();
        assert_eq!(v.get("api").unwrap(), "k");
        assert_eq!(v.expires_at("api"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_whole_file_reference_reads_the_file_at_each_use() {
        let dir = std::env::temp_dir().join(format!("wicket-vault-raw-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("api-key");
        std::fs::write(&key, "key-1\n").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let v = Vault::new(dir.join("vault"));
        assert!(v.link("api", key.to_str().unwrap(), None, Some("/exp"), None).is_err(), "no expiry without a JSON pointer");
        v.link("api", key.to_str().unwrap(), None, None, None).unwrap();
        assert_eq!(v.get("api").unwrap(), "key-1", "trimmed");
        std::fs::write(&key, "key-2").unwrap();
        assert_eq!(v.get("api").unwrap(), "key-2", "re-read, never copied");
        assert!(
            !std::fs::read_dir(dir.join("vault"))
                .unwrap()
                .any(|e| std::fs::read_to_string(e.unwrap().path()).unwrap_or_default().contains("key-")),
            "the vault holds only the reference"
        );
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(v.get("api").is_err(), "world-readable source refused");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The `system.posix_acl_access` bytes for these (tag, perm, id) entries.
    fn acl_bytes(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut b = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in entries {
            b.extend(tag.to_le_bytes());
            b.extend(perm.to_le_bytes());
            b.extend(id.to_le_bytes());
        }
        b
    }

    const UNDEF: u32 = u32::MAX;

    /// An ACL like `setfacl -m u:wicket:r` on an owner-only file makes, plus `extra` entries,
    /// with the owning group's and others' permissions and the mask given.
    fn acl(group: u16, mask: u16, other: u16, extra: &[(u16, u16, u32)]) -> Vec<AclEntry> {
        let mut e = vec![(0x01, 6, UNDEF), (0x02, 4, 1000)];
        e.extend_from_slice(extra);
        e.extend([(0x04, group, UNDEF), (0x10, mask, UNDEF), (0x20, other, UNDEF)]);
        parse_acl(&acl_bytes(&e)).unwrap()
    }

    #[test]
    fn the_acl_parser_reads_the_xattr_format() {
        let a = parse_acl(&acl_bytes(&[
            (0x01, 6, UNDEF),
            (0x02, 4, 1000),
            (0x04, 0, UNDEF),
            (0x08, 5, 50),
            (0x10, 4, UNDEF),
            (0x20, 0, UNDEF),
        ]))
        .unwrap();
        assert_eq!(a.len(), 6);
        assert_eq!(a[1], AclEntry { tag: AclTag::User, perm: 4, id: 1000 });
        assert_eq!(a[3], AclEntry { tag: AclTag::Group, perm: 5, id: 50 });
        assert_eq!(a[4].tag, AclTag::Mask);
        assert!(parse_acl(&[2, 0, 0, 0]).unwrap().is_empty());
        assert!(parse_acl(&[]).is_err(), "too short");
        assert!(parse_acl(&acl_bytes(&[(0x01, 6, UNDEF)])[..10]).is_err(), "truncated entry");
        let mut v1 = acl_bytes(&[(0x01, 6, UNDEF)]);
        v1[0] = 1;
        assert!(parse_acl(&v1).is_err(), "unknown version");
        assert!(parse_acl(&acl_bytes(&[(0x40, 6, UNDEF)])).is_err(), "unknown tag");
    }

    #[test]
    fn an_acl_may_grant_read_to_the_reader_alone() {
        assert!(acl_readers(&acl(0, 4, 0, &[]), 1000).is_empty(), "only the reader: accepted");
        assert_eq!(acl_readers(&acl(0, 4, 0, &[]), 1001), ["user 1000"], "the named user isn't us");
        assert_eq!(acl_readers(&acl(0, 4, 0, &[(0x02, 4, 1002)]), 1000), ["user 1002"], "another user");
        assert_eq!(acl_readers(&acl(0, 4, 0, &[(0x08, 4, 50)]), 1000), ["group 50"], "a named group");
        assert_eq!(acl_readers(&acl(4, 4, 0, &[]), 1000), ["its group"], "the owning group");
        assert_eq!(acl_readers(&acl(0, 4, 4, &[]), 1000), ["others"], "others, unmasked");
        assert_eq!(acl_readers(&acl(0, 0, 4, &[]), 1000), ["others"], "the mask doesn't limit others");
        // The mask can only take away: entries it doesn't let read are no readers.
        assert!(acl_readers(&acl(4, 0, 0, &[(0x08, 4, 50), (0x02, 4, 1002)]), 1000).is_empty());
        assert!(acl_readers(&acl(2, 6, 0, &[(0x08, 2, 50)]), 1000).is_empty(), "write isn't read");
        // Without a mask entry nothing is masked.
        let no_mask = parse_acl(&acl_bytes(&[(0x01, 6, UNDEF), (0x04, 4, UNDEF), (0x20, 0, UNDEF)])).unwrap();
        assert_eq!(acl_readers(&no_mask, 1000), ["its group"]);
    }

    #[test]
    fn a_file_shared_with_the_reader_by_acl_is_accepted() {
        let dir = std::env::temp_dir().join(format!("wicket-vault-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("api-key");
        std::fs::write(&key, "key-1").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let me = unsafe { libc::geteuid() };
        let setfacl = |spec: &str| {
            std::process::Command::new("setfacl").args(["-m", spec]).arg(&key).output().map(|o| o.status.success()).unwrap_or(false)
        };
        if !setfacl(&format!("u:{me}:r")) || access_acl(&key).is_none() {
            eprintln!("skipped: setfacl or ACLs aren't available here");
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let v = Vault::new(dir.join("vault"));
        v.link("api", key.to_str().unwrap(), None, None, None).unwrap();
        assert_ne!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o070, 0, "the mask shows in the group bits");
        assert_eq!(v.get("api").unwrap(), "key-1", "readable by the reader alone");
        assert!(setfacl(&format!("u:{}:r", me.wrapping_add(1))));
        let e = v.get("api").unwrap_err().to_string();
        assert!(e.contains(&format!("user {}", me.wrapping_add(1))), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn private(path: &std::path::Path, body: &str) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    /// A file wicket can't read (here: mode 000, as a login whose ACL a refresh dropped): the error
    /// says how to link it through the helper instead (#350).
    #[test]
    fn an_unreadable_link_says_how_to_use_the_helper() {
        let d = std::env::temp_dir().join(format!("wicket-vault-eacces-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("creds.json");
        private(&f, r#"{"o":{"accessToken":"sk"}}"#);
        let v = Vault::new(d.join("vault"));
        v.link("login", f.to_str().unwrap(), Some("/o/accessToken"), None, None).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&f).is_ok() {
            eprintln!("skipped: this process reads mode-000 files (root)");
            return;
        }
        let e = format!("{:#}", v.get("login").unwrap_err());
        assert!(e.contains("--via-helper") && e.contains("wicket secret serve") && e.contains("ermission denied"), "{e}");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// The model proxy's read (#350): a value that can't be read now is tried again for a while (a
    /// refresh rewriting the file), and then the error names the secret and the cause.
    #[tokio::test]
    async fn a_failed_read_is_retried_then_named() {
        let d = std::env::temp_dir().join(format!("wicket-vault-retry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("creds.json");
        private(&f, r#"{"o":{"accessToken":"sk-1"}}"#);
        let v = Vault::new(d.join("vault"));
        v.link("login", f.to_str().unwrap(), Some("/o/accessToken"), None, None).unwrap();
        v.set_hosts("login", &["api.example.com".into()]).unwrap();
        let patience = std::time::Duration::from_secs(3);

        // The owner is mid-rewrite: the file is gone, then back with a new token.
        std::fs::remove_file(&f).unwrap();
        let f2 = f.clone();
        let back = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            private(&f2, r#"{"o":{"accessToken":"sk-2"}}"#);
        });
        assert_eq!(v.get_for_patiently("login", "api.example.com", patience).await.unwrap(), "sk-2");
        back.join().unwrap();

        // Still unreadable when patience runs out: one error, naming the secret and the cause.
        std::fs::remove_file(&f).unwrap();
        let t = std::time::Instant::now();
        let e = v.get_for_patiently("login", "api.example.com", std::time::Duration::from_millis(600)).await.unwrap_err();
        assert!(t.elapsed() >= std::time::Duration::from_millis(600));
        let u = e.downcast_ref::<SecretUnavailable>().expect("typed");
        assert_eq!(u.name, "login");
        assert!(u.tries > 1, "retried: {u}");
        let msg = e.to_string();
        assert!(msg.starts_with("secret \"login\" could not be read") && msg.contains("missing"), "{msg}");

        // A host it isn't bound to is refused at once, not retried.
        let t = std::time::Instant::now();
        let e = v.get_for_patiently("login", "evil.example", patience).await.unwrap_err();
        assert!(t.elapsed() < std::time::Duration::from_secs(1) && e.downcast_ref::<SecretUnavailable>().is_none(), "{e}");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// A link via the helper: wicket never reads the file; the helper answers with the value and
    /// its expiry, picked up at every use (#350).
    #[test]
    fn a_link_via_the_helper_reads_through_it() {
        let d = std::env::temp_dir().join(format!("wicket-vault-helper-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("creds.json");
        private(&f, r#"{"o":{"accessToken":"sk-h","refreshToken":"rt","expiresAt":32503680000000}}"#);
        // SAFETY: a plain getter.
        let me = unsafe { libc::geteuid() };
        let sock = format!("@wicket-vault-test.{}", std::process::id());
        let served = vec![format!("login={}#/o/accessToken#/o/expiresAt", f.display()).parse().unwrap()];
        let l = crate::secret_helper::bind(&sock).unwrap();
        std::thread::spawn(move || crate::secret_helper::serve(l, vec![me], served));
        let v = Vault::new(d.join("vault"));
        let h = crate::secret_helper::HelperRef { uid: me, socket: sock };
        v.link_via_helper("login", &h, Some(f.to_str().unwrap()), None).unwrap();
        assert_eq!(v.helper_of("login"), Some(h.clone()));
        assert_eq!(v.get("login").unwrap(), "sk-h");
        assert_eq!(v.expires_at("login"), Some(32503680000000));
        let kept = std::fs::read_to_string(d.join("vault/login.ref")).unwrap();
        assert!(!kept.contains("sk-h") && !kept.contains("rt\""), "{kept}");
        // A helper that isn't there: the link is refused.
        let gone = crate::secret_helper::HelperRef { uid: me, socket: format!("@wicket-vault-test.{}.gone", std::process::id()) };
        assert!(v.link_via_helper("other", &gone, None, None).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
