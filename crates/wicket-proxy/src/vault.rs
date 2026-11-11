//! The PoC vault: one file per secret under `~/.config/wicket/secrets`, mode 0600. Secrets are read
//! only by the enforcement points and never written into a sandbox, a log or the audit chain.
//!
//! A secret can also be a **reference** (`<name>.ref`): a file plus a JSON pointer, re-read on every
//! use. That is how wicket uses the Claude login already on the host: it reads the current access
//! token at request time and never touches the refresh token or writes the file, so the host's Claude
//! Code keeps refreshing its own login.

use anyhow::{bail, Context, Result};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Vault {
    dir: PathBuf,
}

impl Vault {
    pub fn new(dir: PathBuf) -> Vault {
        Vault { dir }
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

    pub fn has(&self, name: &str) -> bool {
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

    pub fn list(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|n| !n.ends_with(".tmp"))
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

#[cfg(test)]
mod tests {
    use super::*;

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
