//! The PoC vault: one file per secret under `~/.config/wicket/secrets`, mode 0600. Secrets are read
//! only by the enforcement points and never written into a sandbox, a log or the audit chain.
//!
//! A secret can also be a **reference** (`<name>.ref`): a file plus a JSON pointer, re-read on every
//! use. That is how wicket uses the Claude login already on the host: it reads the current access
//! token at request time and never touches the refresh token or writes the file, so the host's Claude
//! Code keeps refreshing its own login.
//!
//! **Each secret is bound to the hosts it may be sent to** (`<name>.hosts`, written by whoever stores
//! it: root, on a system install). The egress proxy, credential swaps and the model proxy send a
//! secret only to those hosts, whatever a manifest asks; a secret with no hosts is sent nowhere.
//! `claude-oauth` defaults to `api.anthropic.com`.

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

    /// Whether this vault's secrets come from a source (a node's cache) rather than a directory.
    pub fn is_sourced(&self) -> bool {
        self.source.is_some()
    }

    /// A vault whose secrets come from `source` only (a node's cache, #152).
    pub fn from_source(source: std::sync::Arc<dyn SecretSource>) -> Vault {
        Vault { dir: PathBuf::from("/nonexistent/wicket-sealed-vault"), source: Some(source) }
    }

    /// When a reference's current value expires upstream (Unix ms), if its file says so (e.g. the
    /// Claude login's access token): a node holding a copy drops it then (#152).
    pub fn expires_at(&self, name: &str) -> Option<i64> {
        let r = self.path(name).ok()?.with_extension("ref");
        let spec: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(r).ok()?).ok()?;
        let (file, ep) = (spec.get("file")?.as_str()?, spec.get("expires_pointer")?.as_str()?);
        let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(file).ok()?).ok()?;
        doc.pointer(ep)?.as_i64()
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
        let r = p.with_extension("ref");
        if r.exists() {
            return self.get_ref(name, &r);
        }
        let meta = std::fs::metadata(&p).with_context(|| format!("secret {name:?} is not set (run: wicket secret set {name})"))?;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!("secret file {} must not be readable by group or others", p.display());
        }
        let v = std::fs::read_to_string(&p)?;
        let v = v.trim().to_string();
        if v.is_empty() {
            bail!("secret {name:?} is empty");
        }
        Ok(v)
    }

    fn get_ref(&self, name: &str, r: &std::path::Path) -> Result<String> {
        let spec: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(r)?)?;
        let file = spec.get("file").and_then(|v| v.as_str()).with_context(|| format!("{name}.ref needs \"file\""))?;
        // No pointer: the whole file is the secret (e.g. an API key file).
        let pointer = spec.get("pointer").and_then(|v| v.as_str());
        let meta = std::fs::metadata(file).with_context(|| format!("secret {name} refers to {file}, which is missing"))?;
        if meta.permissions().mode() & 0o077 != 0 {
            bail!("{file} (referenced by secret {name}) must not be readable by group or others");
        }
        let Some(pointer) = pointer else {
            let v = std::fs::read_to_string(file)?;
            if v.trim().is_empty() {
                bail!("secret {name} is empty");
            }
            return Ok(v.trim().to_string());
        };
        let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(file)?)?;
        if let Some(ep) = spec.get("expires_pointer").and_then(|v| v.as_str()) {
            if let Some(ms) = doc.pointer(ep).and_then(|v| v.as_i64()) {
                let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
                if ms <= now_ms {
                    bail!("secret {name}: the referenced token has expired; its owner (e.g. Claude Code on the host) must refresh it");
                }
            }
        }
        let v = doc.pointer(pointer).and_then(|v| v.as_str()).with_context(|| format!("secret {name}: nothing at {pointer} in {file}"))?;
        if v.trim().is_empty() {
            bail!("secret {name} is empty");
        }
        Ok(v.trim().to_string())
    }

    /// The file a linked secret refers to (None for a stored secret).
    pub fn linked_file(&self, name: &str) -> Option<PathBuf> {
        let r = self.path(name).ok()?.with_extension("ref");
        let spec: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(r).ok()?).ok()?;
        spec.get("file")?.as_str().map(PathBuf::from)
    }

    /// For a secret linked to a JSON field, the object that holds it, as the file has it now (e.g.
    /// the Claude login's `claudeAiOauth`, for its non-secret fields: scopes, subscription type).
    /// None for a stored secret or a whole-file link.
    pub fn linked_object(&self, name: &str) -> Option<serde_json::Value> {
        let r = self.path(name).ok()?.with_extension("ref");
        let spec: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(r).ok()?).ok()?;
        let file = spec.get("file")?.as_str()?;
        let pointer = spec.get("pointer")?.as_str()?;
        let parent = &pointer[..pointer.rfind('/')?];
        let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(file).ok()?).ok()?;
        doc.pointer(parent).filter(|v| v.is_object()).cloned()
    }

    /// Makes `name` a reference to another file (never copied into the vault): a JSON field in it,
    /// or with no `pointer`, the whole file, trimmed.
    pub fn link(&self, name: &str, file: &str, pointer: Option<&str>, expires_pointer: Option<&str>) -> Result<()> {
        if pointer.is_none() && expires_pointer.is_some() {
            bail!("an expiry pointer needs a JSON pointer: a whole-file reference has no fields");
        }
        let p = self.path(name)?;
        std::fs::create_dir_all(&self.dir)?;
        std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))?;
        let spec = serde_json::json!({ "file": file, "pointer": pointer, "expires_pointer": expires_pointer });
        let r = p.with_extension("ref");
        std::fs::write(&r, serde_json::to_vec_pretty(&spec)?)?;
        std::fs::set_permissions(&r, std::fs::Permissions::from_mode(0o600))?;
        let _ = std::fs::remove_file(&p);
        self.get(name).map(|_| ())
    }

    /// The hosts `name` may be sent to: its `.hosts` list, else the default for well-known names,
    /// else none.
    pub fn hosts(&self, name: &str) -> Vec<String> {
        if let Some(s) = &self.source {
            return s.hosts(name);
        }
        let Ok(p) = self.path(name) else { return vec![] };
        match std::fs::read(p.with_extension("hosts")) {
            Ok(b) => serde_json::from_slice::<Vec<String>>(&b).unwrap_or_default(),
            Err(_) => default_hosts(name),
        }
    }

    /// Binds `name` to exactly these hosts (patterns: `api.example.com`, `*.example.com`).
    pub fn set_hosts(&self, name: &str, hosts: &[String]) -> Result<()> {
        let p = self.path(name)?;
        let mut v = Vec::new();
        for h in hosts {
            let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
            check_host_pattern(&h)?;
            if !v.contains(&h) {
                v.push(h);
            }
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
        for f in [p.clone(), p.with_extension("ref"), p.with_extension("hosts")] {
            match std::fs::remove_file(&f) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
                _ => {}
            }
        }
        Ok(())
    }

    pub fn list(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| !n.ends_with(".tmp") && !n.ends_with(".hosts") && !n.ends_with(".hosts-tmp"))
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

/// Hosts a well-known secret may go to when nobody bound it.
fn default_hosts(name: &str) -> Vec<String> {
    match name {
        "claude-oauth" => vec!["api.anthropic.com".into()],
        _ => vec![],
    }
}

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

#[cfg(test)]
mod tests {
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
        // claude-oauth has a default; an explicit binding replaces it.
        v.set("claude-oauth", "t").unwrap();
        assert!(v.allows("claude-oauth", "api.anthropic.com") && !v.allows("claude-oauth", "attacker.example"));
        v.set_hosts("claude-oauth", &["127.0.0.1".into()]).unwrap();
        assert!(!v.allows("claude-oauth", "api.anthropic.com") && v.allows("claude-oauth", "127.0.0.1"));
        for bad in ["*", "*.com", "a/b", "", "-a.com", "a..com", "*.*.com"] {
            assert!(v.set_hosts("gh", &[bad.into()]).is_err(), "{bad:?}");
        }
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
        v.link("claude-oauth", creds.to_str().unwrap(), Some("/o/accessToken"), Some("/o/expiresAt")).unwrap();
        assert_eq!(v.get("claude-oauth").unwrap(), "tok-1");
        write("tok-2", far); // the owner refreshed it: we see the new value
        assert_eq!(v.get("claude-oauth").unwrap(), "tok-2");
        write("tok-3", 1000); // expired
        assert!(v.get("claude-oauth").unwrap_err().to_string().contains("expired"));
        std::fs::set_permissions(&creds, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(v.get("claude-oauth").is_err(), "world-readable source refused");
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
        assert!(v.link("api", key.to_str().unwrap(), None, Some("/exp")).is_err(), "no expiry without a JSON pointer");
        v.link("api", key.to_str().unwrap(), None, None).unwrap();
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
}
