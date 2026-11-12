//! `wicket doctor`: is this host ready, and is it safe? Through wicketd, the caller's side checks
//! what the caller must not be able to do (daemon::client), and this runs as the wicket user.

use crate::{daemon, data_dir, issuer_key_path, ledger_path, reap, trust_domain};
use anyhow::{bail, Result};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use wicket_proxy::vault::Vault;
use wicket_store::Ledger;

/// Where deploy/install.sh keeps the console's arguments.
pub const CONSOLE_ENV: &str = "/etc/wicket/console.env";

struct Report {
    ok: bool,
}

impl Report {
    fn good(&self, s: impl AsRef<str>) {
        println!("{}", s.as_ref());
    }
    fn bad(&mut self, s: impl AsRef<str>) {
        println!("{}", s.as_ref());
        self.ok = false;
    }
}

pub async fn doctor(image: &str) -> Result<()> {
    let mut r = Report { ok: true };
    // SAFETY: plain getters.
    let me = unsafe { libc::geteuid() };
    let user = daemon::proto::user_name(me).unwrap_or_else(|| me.to_string());
    let socket = std::env::var_os("WICKET_DAEMON_SOCKET").map(std::path::PathBuf::from).unwrap_or_else(|| daemon::SOCKET_PATH.into());
    let system = std::fs::metadata(&socket).is_ok_and(|m| m.uid() == me);
    if system {
        r.good(format!("mode: system install, as {user} (uid {me})"));
        system_checks(&mut r, me, &socket);
    } else {
        r.good(format!(
            "mode: development (one user, no wicketd): INSECURE. Anything running as {user} can connect to run sockets and pass as a run, \
             read the ledger and the vault, and approve without a passkey (wicket approve). For real use, install wicketd: deploy/install.sh"
        ));
    }

    let d = wicket_sandbox::Docker::from_env();
    match d.runtimes().await {
        Ok(rt) => {
            r.good(format!("docker: ok (runtimes: {})", rt.join(", ")));
            match d.runtime_args("runsc").await {
                Ok(Some(args)) if args.iter().any(|a| a == "--host-uds=open") => r.good("gVisor (runsc): registered, with --host-uds=open"),
                Ok(Some(args)) => r.bad(format!(
                    "gVisor (runsc): registered without --host-uds=open (args: [{}]): boxes can't reach their unix sockets",
                    args.join(", ")
                )),
                Ok(None) => r.bad("gVisor (runsc) is not registered: zones default to isolation: gvisor"),
                Err(e) => r.bad(format!("gVisor (runsc): NOT OK ({e})")),
            }
        }
        Err(e) => r.bad(format!("docker: NOT OK ({e})")),
    }
    match d.image_exists(image).await {
        Ok(true) => r.good(format!("image {image}: present")),
        _ => r.bad(format!("image {image}: missing (run: wicket image)")),
    }
    match wicket_identity::Issuer::load(&issuer_key_path(), trust_domain().as_deref()) {
        Ok(i) => r.good(format!("identity issuer: {}", i.issuer_id())),
        Err(e) => r.bad(format!("identity issuer: NOT OK ({e})")),
    }
    let v = Vault::new(Vault::default_dir());
    let names = v.list();
    r.good(format!("vault: {} secret(s){}", names.len(), if names.is_empty() { String::new() } else { format!(": {}", names.join(", ")) }));
    if !v.has("claude-oauth") {
        r.good("  no 'claude-oauth' secret: real runs need your Claude subscription token");
        r.good(format!("  (run `claude setup-token`, then: {}wicket secret set claude-oauth)", if system { "sudo " } else { "" }));
    }
    placement(&mut r, &v);
    let l = Ledger::open(&ledger_path())?;
    r.good(format!("ledger: {} (audit chain OK, {} records)", ledger_path().display(), l.verify_audit()?));
    console(&mut r, &l, system).await;
    if let Ok(all) = reap::reap(&d, &l, true).await {
        let orphans: Vec<_> = all.iter().filter(|r| matches!(r.verdict, reap::Verdict::Orphan(_))).map(|r| r.name.as_str()).collect();
        if orphans.is_empty() {
            r.good(format!("boxes: {} running, none orphaned", all.len()));
        } else {
            r.good(format!("boxes: {} orphaned, with nothing behind them: {} (run: wicket reap)", orphans.len(), orphans.join(", ")));
        }
    }
    if !r.ok {
        bail!("environment not ready");
    }
    Ok(())
}

/// The wicket user's own view of a system install: its data is its alone, and nobody else can
/// reach Docker.
fn system_checks(r: &mut Report, me: u32, socket: &Path) {
    let data = data_dir();
    match std::fs::metadata(&data) {
        Ok(m) if m.uid() == me && m.permissions().mode() & 0o077 == 0 => r.good(format!("data {}: ours, mode 0700", data.display())),
        Ok(m) => r.bad(format!(
            "data {}: NOT OK: owner uid {}, mode {:o}; it must be ours and 0700",
            data.display(),
            m.uid(),
            m.permissions().mode() & 0o7777
        )),
        Err(e) => r.bad(format!("data {}: NOT OK ({e})", data.display())),
    }
    // Everything secret must live inside it (the units set HOME and WICKET_HOME to it).
    for (what, p) in [("vault", Vault::default_dir()), ("issuer key", issuer_key_path()), ("ledger", ledger_path())] {
        if !p.starts_with(&data) {
            r.bad(format!("{what} {}: NOT OK: outside the data directory (set HOME and WICKET_HOME to it)", p.display()));
        }
    }
    match std::fs::metadata(socket) {
        Ok(m) if m.file_type().is_socket() => {
            r.good(format!("wicketd socket {}: ours, mode {:o}", socket.display(), m.permissions().mode() & 0o777))
        }
        _ => r.bad(format!("wicketd socket {}: NOT OK: not a socket", socket.display())),
    }
    match std::fs::read_to_string(daemon::policy::POLICY_PATH).map_err(anyhow::Error::from).and_then(|s| daemon::policy::Policy::parse(&s))
    {
        Ok(p) => r.good(format!(
            "policy {}: read [{}], run [{}], revoke [{}]; approving needs root or a passkey",
            daemon::policy::POLICY_PATH,
            grantees(&p.read),
            grantees(&p.run),
            grantees(&p.revoke)
        )),
        Err(e) => r.bad(format!("policy {}: NOT OK ({e})", daemon::policy::POLICY_PATH)),
    }
    // Who else can reach Docker: the docker group is root on the host.
    let members = docker_members();
    let others: Vec<_> = members.iter().filter(|u| daemon::proto::user_name(me).as_deref() != Some(u.as_str())).cloned().collect();
    if others.is_empty() {
        r.good("docker group: only us");
    } else {
        r.bad(format!(
            "docker group: NOT OK: {} {} in it too, which is root on this host (sudo gpasswd -d USER docker)",
            others.join(", "),
            if others.len() == 1 { "is" } else { "are" }
        ));
    }
    if !members.iter().any(|u| daemon::proto::user_name(me).as_deref() == Some(u.as_str())) && std::env::var_os("DOCKER_HOST").is_none() {
        r.bad("docker group: NOT OK: we are not in it (sudo usermod -aG docker wicket, then restart wicketd)");
    }
}

fn grantees(g: &daemon::policy::Grantees) -> String {
    g.users.iter().map(|u| format!("user {u}")).chain(g.groups.iter().map(|x| format!("group {x}"))).collect::<Vec<_>>().join(", ")
}

/// The docker group's members, from the group file and from users whose primary group it is.
fn docker_members() -> Vec<String> {
    let mut out = vec![];
    let Some(gid) = daemon::proto::group_id("docker") else { return out };
    if let Ok(g) = std::fs::read_to_string("/etc/group") {
        for line in g.lines() {
            let f: Vec<_> = line.split(':').collect();
            if f.len() == 4 && f[2].parse::<u32>().ok() == Some(gid) {
                out.extend(f[3].split(',').filter(|s| !s.is_empty()).map(String::from));
            }
        }
    }
    if let Ok(p) = std::fs::read_to_string("/etc/passwd") {
        for line in p.lines() {
            let f: Vec<_> = line.split(':').collect();
            if f.len() >= 4 && f[3].parse::<u32>().ok() == Some(gid) {
                out.push(f[0].to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The placement backend (#37): configured, and its credentials in the vault (never called).
fn placement(r: &mut Report, v: &Vault) {
    match crate::capacity::PlacementConfig::load() {
        Ok(None) => r.good("placement: not configured (boxes run here and on enrolled nodes)"),
        Ok(Some(c)) => match (&c.backend, &c.vultr) {
            (crate::capacity::Backend::Vultr, Some(vs)) if v.has(&vs.api_key_secret) => {
                r.good(format!("placement: vultr, API key secret {:?} present (not called)", vs.api_key_secret))
            }
            (crate::capacity::Backend::Vultr, Some(vs)) => {
                r.bad(format!("placement: vultr, NOT OK: no secret {:?} (sudo wicket secret set {})", vs.api_key_secret, vs.api_key_secret))
            }
            (crate::capacity::Backend::Vultr, None) => r.bad("placement: vultr, NOT OK: no vultr: settings"),
            (crate::capacity::Backend::Static, _) => r.good(format!("placement: static, {} host(s)", c.static_hosts.len())),
        },
        Err(e) => r.bad(format!("placement: NOT OK ({e:#})")),
    }
}

/// The console (#23): the options it is started with make sense, it is up, and a passkey exists.
async fn console(r: &mut Report, l: &Ledger, system: bool) {
    let args = if system {
        match std::fs::read_to_string(CONSOLE_ENV) {
            Ok(s) => console_args(&s),
            Err(_) => {
                r.bad(format!("console: NOT OK: no {CONSOLE_ENV} (deploy/install.sh writes it)"));
                return;
            }
        }
    } else {
        vec![]
    };
    use clap::Parser;
    let parsed = crate::Cli::try_parse_from(["wicket".to_string(), "serve".into()].into_iter().chain(args.iter().cloned()));
    let Some((opts, _)) = parsed.ok().and_then(|c| crate::serve_opts(c.cmd)) else {
        r.bad(format!("console: NOT OK: bad arguments in {CONSOLE_ENV}: {}", args.join(" ")));
        return;
    };
    match crate::serve::describe(&opts) {
        Ok((origin, rp_id, how, addr)) => {
            let up = tokio::time::timeout(std::time::Duration::from_secs(2), tokio::net::TcpStream::connect(addr))
                .await
                .is_ok_and(|c| c.is_ok());
            let line =
                format!("console: {origin} (passkeys for {rp_id}; {how}; listening on {addr}: {})", if up { "up" } else { "not running" });
            if system && !up {
                r.bad(format!("{line}; sudo systemctl status wicket-console"));
            } else {
                r.good(line);
            }
            if !origin.starts_with("https://") && !origin.starts_with("http://localhost") && !origin.starts_with("http://127.0.0.1") {
                r.bad("  NOT OK: passkeys need https:// or localhost");
            }
            if origin.starts_with("http://") && system {
                r.good("  reach it from your devices with an ssh tunnel, or serve it over HTTPS (README: the console from a phone)");
            }
        }
        Err(e) => r.bad(format!("console: NOT OK ({e:#})")),
    }
    match l.operator_credentials(&wicket_core::TenantId::single()) {
        Ok(c) if c.is_empty() => {
            r.good(format!("  no passkey enrolled yet: {}wicket operator enrol-link --origin ORIGIN", if system { "sudo " } else { "" }))
        }
        Ok(c) => r.good(format!("  {} passkey(s) enrolled", c.len())),
        Err(e) => r.bad(format!("  passkeys: NOT OK ({e})")),
    }
}

/// WICKET_CONSOLE_ARGS from an environment file, split as systemd splits `$VAR` (on whitespace).
pub fn console_args(env_file: &str) -> Vec<String> {
    for line in env_file.lines() {
        if let Some(v) = line.trim().strip_prefix("WICKET_CONSOLE_ARGS=") {
            let v = v.trim();
            let v = v.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(v);
            return v.split_whitespace().map(String::from).collect();
        }
    }
    vec![]
}

#[cfg(test)]
mod tests {
    #[test]
    fn console_args_are_read_like_systemd_does() {
        let f = "# comment\nWICKET_CONSOLE_ARGS=\"--listen 127.0.0.1:8787 --no-bootstrap-link\"\n";
        assert_eq!(super::console_args(f), ["--listen", "127.0.0.1:8787", "--no-bootstrap-link"]);
        assert_eq!(super::console_args("WICKET_CONSOLE_ARGS=--origin https://c.example.com"), ["--origin", "https://c.example.com"]);
        assert!(super::console_args("OTHER=1").is_empty());
    }
}
