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
                    if !hosts.is_empty() {
                        v.set_hosts(&name, &hosts)?;
                    }
                    println!("stored secret {name}; {}", secret_hosts_line(&v, &name));
                }
                SecretCmd::Link { name, file, pointer, expires_pointer, hosts } => {
                    v.link(&name, &file, pointer.as_deref(), expires_pointer.as_deref())?;
                    if !hosts.is_empty() {
                        v.set_hosts(&name, &hosts)?;
                    }
                    println!(
                        "secret {name} now refers to {file}{} (read at each use; never copied); {}",
                        pointer.as_deref().map(|p| format!("#{p}")).unwrap_or_default(),
                        secret_hosts_line(&v, &name)
                    );
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
        /// The only hosts it may be sent to (comma-separated; `*.example.com` for every host under
        /// it). Without it, the secret keeps the hosts it had; a secret with none is sent nowhere
        /// (claude-oauth defaults to api.anthropic.com).
        #[arg(long, value_delimiter = ',')]
        hosts: Vec<String>,
    },
    /// List secret names and the hosts each may be sent to (never values).
    List,
    /// Remove a secret (a reference: only the reference). Nodes holding a copy delete it when their
    /// run's lease next reaches them, within seconds while connected (#152).
    Rm { name: String },
    /// Bind a secret to the only hosts it may be sent to, replacing its list.
    Hosts {
        name: String,
        #[arg(long, value_delimiter = ',', required = true)]
        hosts: Vec<String>,
    },
    /// Make a secret a reference to a JSON field in another file, re-read on every use (never copied).
    /// E.g. the Claude login on this host:
    /// wicket secret link claude-oauth --file ~/.claude/.credentials.json --pointer /claudeAiOauth/accessToken --expires-pointer /claudeAiOauth/expiresAt
    Link {
        name: String,
        #[arg(long)]
        file: String,
        /// A JSON pointer into the file (e.g. /claudeAiOauth/accessToken). Without one, the whole file
        /// is the secret, trimmed (e.g. an API key file).
        #[arg(long)]
        pointer: Option<String>,
        #[arg(long)]
        expires_pointer: Option<String>,
        /// The only hosts it may be sent to (as for `secret set`).
        #[arg(long, value_delimiter = ',')]
        hosts: Vec<String>,
    },
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
