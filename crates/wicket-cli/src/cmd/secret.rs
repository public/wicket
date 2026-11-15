//! `wicket secret`: the vault, by name and binding.
//!
//! One module per command group, out of `main.rs` (#220): a PR that changes one group's flags or
//! handling touches only its own file.

use crate::*;

/// Runs one of this group's commands.
pub async fn dispatch(c: Cmd) -> Result<()> {
    match c {
        Cmd::Secret { cmd } => {
            let v = Vault::new(Vault::default_dir());
            match cmd {
                SecretCmd::Set { name, hosts } => {
                    let value = if std::io::stdin().is_terminal() {
                        rpassword::prompt_password(format!("value for {name} (not echoed): "))?
                    } else {
                        let mut s = String::new();
                        std::io::stdin().read_to_string(&mut s)?;
                        s
                    };
                    if value.trim().is_empty() {
                        bail!("empty value");
                    }
                    v.set(&name, &value)?;
                    bind(&v, &name, &hosts)?;
                    println!("stored secret {name}; {}", secret_hosts_line(&v, &name));
                }
                SecretCmd::Link { name, file, pointer, expires_pointer, hosts } => {
                    let captured = link(&v, &name, &file, pointer.as_deref(), expires_pointer.as_deref())?;
                    bind(&v, &name, &hosts)?;
                    println!(
                        "secret {name} now refers to {file}{} (read at each use; never copied); {}",
                        pointer.as_deref().map(|p| format!("#{p}")).unwrap_or_default(),
                        secret_hosts_line(&v, &name)
                    );
                    match &captured {
                        Some(Ok(_)) => {
                            println!("kept the login's account fields with it, for Remote Control boxes (re-link to refresh them)")
                        }
                        Some(Err(why)) => eprintln!("warning: linked, but {why}"),
                        None => {}
                    }
                }
                SecretCmd::Hosts { name, hosts } => {
                    if !v.has(&name) {
                        bail!("no secret {name}");
                    }
                    v.set_hosts(&name, &hosts)?;
                    println!("secret {name}: {}", secret_hosts_line(&v, &name));
                }
                SecretCmd::Rm { name } => {
                    if !v.has(&name) {
                        bail!("no secret {name}");
                    }
                    v.remove(&name)?;
                    println!("secret {name} removed");
                }
                SecretCmd::List => {
                    for n in v.list() {
                        let base = n.strip_suffix(" (reference)").unwrap_or(&n);
                        println!("{n}  {}", secret_hosts_line(&v, base));
                    }
                }
            }
            Ok(())
        }
        _ => unreachable!("dispatched to the wrong command group"),
    }
}

#[derive(Subcommand)]
pub enum SecretCmd {
    /// Store a secret. Prompts without echo, or reads stdin when it isn't a terminal.
    Set {
        name: String,
        /// The only host names it may be sent to (comma-separated; `*.example.com` for every name
        /// under it). Without it, the secret keeps the host names it had; a new one with none is sent nowhere,
        /// unless it is a harness's default model secret: then it goes to that harness's model host name.
        #[arg(long, value_delimiter = ',')]
        hosts: Vec<String>,
    },
    /// List secret names and the host names each may be sent to (never values).
    List,
    /// Remove a secret (a reference: only the reference). Nodes holding a copy for a run delete it
    /// when the control host next checks that run's secrets, within seconds while connected (#152).
    Rm { name: String },
    /// Bind a secret to the only host names it may be sent to, replacing its list.
    Hosts {
        name: String,
        #[arg(long, value_delimiter = ',', required = true)]
        hosts: Vec<String>,
    },
    /// Make a secret a reference to a JSON field in another file, re-read on every use (never copied):
    /// e.g. a harness's login on this host (docs/how-to/store-and-link-secrets.md). A harness login's
    /// account fields (never its holder's name) are kept with the reference as they are now, for
    /// Remote Control boxes: re-link to refresh them.
    Link {
        name: String,
        #[arg(long)]
        file: String,
        /// A JSON pointer into the file (e.g. /login/accessToken). Without one, the whole file
        /// is the secret, trimmed (e.g. an API key file).
        #[arg(long)]
        pointer: Option<String>,
        #[arg(long)]
        expires_pointer: Option<String>,
        /// The only host names it may be sent to (as for `secret set`).
        #[arg(long, value_delimiter = ',')]
        hosts: Vec<String>,
    },
}

/// Binds a stored or linked secret: to `hosts` if given; else, if it has no binding yet and is a
/// harness's default model secret, to that harness's model host (its adapter's default route); else
/// it keeps what it had.
pub(crate) fn bind(v: &Vault, name: &str, hosts: &[String]) -> Result<()> {
    if !hosts.is_empty() {
        return v.set_hosts(name, hosts);
    }
    let default = wicket_agent::harness::default_secret_hosts(name);
    if v.hosts(name).is_empty() && !default.is_empty() {
        v.set_hosts(name, &default)?;
    }
    Ok(())
}

/// Links `name` to `file`, keeping with it what the harness whose login it is reads now (#298): a
/// Claude login's account fields, so no box start reads `~/.claude.json`. The capture's outcome
/// (None: no harness's login); a failed capture doesn't stop the link.
pub(crate) fn link(
    v: &Vault,
    name: &str,
    file: &str,
    pointer: Option<&str>,
    expires_pointer: Option<&str>,
) -> Result<Option<std::result::Result<serde_json::Value, String>>> {
    let captured = wicket_agent::harness::link_login_meta(std::path::Path::new(file), pointer);
    v.link(name, file, pointer, expires_pointer, captured.as_ref().and_then(|c| c.as_ref().ok()))?;
    Ok(captured)
}

/// Where a secret may be sent, for terminals.
pub(crate) fn secret_hosts_line(v: &Vault, name: &str) -> String {
    let h = v.hosts(name);
    if h.is_empty() {
        format!("sent to no host (bind it: wicket secret hosts {name} --hosts HOST[,HOST])")
    } else {
        format!("sent only to {}", h.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn remote_manifest() -> wicket_core::manifest::Manifest {
        wicket_agent::load("agent: { name: rc, remote: { name: box } }\nzone: { name: z, llm: { secret: claude-login } }\n").unwrap()
    }

    #[test]
    fn a_link_keeps_the_account_and_a_later_start_uses_it_with_the_config_gone() {
        let d = std::env::temp_dir().join(format!("wicket-secret-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("home/.claude")).unwrap();
        let creds = d.join("home/.claude/.credentials.json");
        std::fs::write(
            &creds,
            r#"{"claudeAiOauth":{"accessToken":"sk-real","refreshToken":"rt","expiresAt":32503680000000,"subscriptionType":"max"}}"#,
        )
        .unwrap();
        std::fs::set_permissions(&creds, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = d.join("home/.claude.json");
        std::fs::write(&config, r#"{"oauthAccount":{"organizationUuid":"org-1","emailAddress":"a@example.com","fullName":"A Person"}}"#)
            .unwrap();
        let v = Vault::new(d.join("vault"));
        let (file, pointer) = (creds.to_str().unwrap(), Some("/claudeAiOauth/accessToken"));

        let captured = link(&v, "claude-login", file, pointer, Some("/claudeAiOauth/expiresAt")).unwrap();
        assert!(matches!(captured, Some(Ok(_))), "{captured:?}");
        let kept = std::fs::read_to_string(d.join("vault/claude-login.ref")).unwrap();
        assert!(kept.contains("org-1") && !kept.contains("fullName") && !kept.contains("A Person"), "{kept}");
        assert!(!kept.contains("sk-real") && !kept.contains("\"rt\""), "no credential kept: {kept}");

        // Claude Code replaced its config, and wicket can't read it any more: a start doesn't need it.
        std::fs::remove_file(&config).unwrap();
        let m = remote_manifest();
        let h = wicket_agent::harness::of(&m).unwrap();
        let meta = h.remote_login_meta(v.linked_object("claude-login").as_ref(), v.link_meta("claude-login").as_ref());
        let w = h.remote_plan(&m, &wicket_core::RunId("run_x".into()), &meta).unwrap();
        let cfg: serde_json::Value = serde_json::from_slice(&w.files.iter().find(|(r, _)| r == "claude/.claude.json").unwrap().1).unwrap();
        assert_eq!(cfg["oauthAccount"], serde_json::json!({ "organizationUuid": "org-1", "emailAddress": "a@example.com" }));
        let creds_in_box = String::from_utf8(w.files.iter().find(|(r, _)| r == "claude/.credentials.json").unwrap().1.clone()).unwrap();
        assert!(creds_in_box.contains("max") && !creds_in_box.contains("sk-real"));

        // Linking without the config still links, says so, and keeps no stale account.
        let captured = link(&v, "claude-login", file, pointer, None).unwrap();
        assert!(captured.unwrap().unwrap_err().contains("re-link"));
        assert_eq!(v.get("claude-login").unwrap(), "sk-real");
        assert_eq!(v.link_meta("claude-login"), None);

        // Another kind of secret is no harness's login: nothing kept.
        let key = d.join("key");
        std::fs::write(&key, "k").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(link(&v, "api", key.to_str().unwrap(), None, None).unwrap().is_none());
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// The vault has no defaults (#255): a harness's default model secret gets its model host when
    /// stored with no binding, as its adapter says; an explicit or existing binding stands.
    #[test]
    fn a_harness_default_model_secret_is_bound_to_its_model_host_when_stored() {
        let d = std::env::temp_dir().join(format!("wicket-secret-bind-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let v = Vault::new(d.join("vault"));
        let s = &wicket_agent::harness::model_secrets()[0].secret;
        let route = wicket_agent::harness::default_secret_hosts(s);
        assert!(!route.is_empty());
        v.set(s, "t").unwrap();
        assert!(v.hosts(s).is_empty(), "the vault itself binds nothing");
        bind(&v, s, &[]).unwrap();
        assert_eq!(v.hosts(s), route);
        bind(&v, s, &["127.0.0.1".into()]).unwrap();
        assert_eq!(v.hosts(s), ["127.0.0.1"]);
        bind(&v, s, &[]).unwrap();
        assert_eq!(v.hosts(s), ["127.0.0.1"], "a binding is kept");
        v.set("other", "t").unwrap();
        bind(&v, "other", &[]).unwrap();
        assert!(v.hosts("other").is_empty(), "any other secret stays unbound");
        std::fs::remove_dir_all(&d).unwrap();
    }
}
