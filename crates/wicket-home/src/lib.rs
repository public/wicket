//! An installation's home (#219): where its data is ([`data_dir`], [`ledger_path`]), its identity
//! issuer ([`issuer`]) and how a run's identity shows ([`verified_identity`]), and who is calling:
//! the principal behind a root run ([`cli_principal`]) and the operator deciding ([`operator`]).
//!
//! A library split from wicket-cli, whose modules nearly all use these, so the ones that need
//! nothing else of the CLI's can leave it too, and have: the node control channel's
//! authentication ([`nodeauth`]), the state store and audit export ([`s3`], [`statestore`],
//! [`audit_export`]), the image policy ([`images_policy`]), program digests ([`program`]), box
//! owners and exit causes ([`owner`], [`exitcause`]) and a driven harness's control channel
//! ([`control`]). wicket-cli imports them all under their old names.

// First, so the modules after it can use say! and say_err!.
#[macro_use]
pub mod out;

pub mod audit_export;
pub mod control;
pub mod exit;
pub mod exitcause;
pub mod images_policy;
pub mod nodeauth;
pub mod owner;
pub mod program;
pub mod s3;
pub mod statestore;

use anyhow::Result;
use std::path::PathBuf;
use wicket_store::Ledger;

pub fn data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("WICKET_HOME") {
        return PathBuf::from(d);
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    home.join(".local/share/wicket")
}

pub fn ledger_path() -> PathBuf {
    data_dir().join("ledger.db")
}

/// The verified identity of the agent running as `run`, for showing to humans: the identity document
/// is checked against the issuer and against the ledger's own row, so an edited row is caught.
/// `at` is the time to check validity at (now for live runs, issue time for history).
pub fn verified_identity(l: &Ledger, run: &str, at: Option<i64>) -> serde_json::Value {
    let row = match l.identity(run) {
        Ok(Some(r)) => r,
        Ok(None) => return serde_json::json!({ "verified": false, "run": run, "error": "no identity was issued for this run" }),
        Err(e) => return serde_json::json!({ "verified": false, "run": run, "error": e.to_string() }),
    };
    let check = || -> anyhow::Result<wicket_identity::AgentClaims> {
        let issuer = issuer()?;
        let c = wicket_identity::verify_identity(&row.jws, &issuer.verifying_key(), at.unwrap_or(row.issued_at))?;
        if c.run != row.run
            || c.tenant != row.tenant
            || c.zone != row.zone
            || c.agent != row.agent
            || c.sub != row.spiffe_id
            || c.parent_run != row.parent_run
        {
            anyhow::bail!("the ledger's record does not match the signed identity");
        }
        Ok(c)
    };
    match check() {
        Ok(c) => {
            if let Ok(Some((r, when, by, reason))) = l.revoked_in_chain(run) {
                let whose = if r == run { "identity".to_string() } else { format!("identity of its ancestor {r}") };
                return serde_json::json!({ "verified": false, "revoked": true, "run": run, "agent": c.agent, "zone": c.zone,
                    "error": format!("{whose} revoked by {by} at {when}: {reason}") });
            }
            let parent_agent = c.parent_run.as_deref().and_then(|p| l.identity(p).ok().flatten()).map(|p| p.agent);
            serde_json::json!({
                "verified": true, "id": c.sub, "agent": c.agent, "zone": c.zone, "tenant": c.tenant, "run": c.run,
                "parent_run": c.parent_run, "parent_agent": parent_agent, "node": c.node, "image": c.image,
                "principal": c.principal, "acting_for": c.chain(), "expires_at": c.exp,
                "manifest_sha256": c.manifest_sha256, "identity_sha256": wicket_identity::identity_digest(&row.jws),
            })
        }
        Err(e) => serde_json::json!({ "verified": false, "run": run, "agent": row.agent, "zone": row.zone, "error": e.to_string() }),
    }
}

/// A request as `wicket pending` and `wicket approve` show it: wicket's own record, with every
/// agent-written field (method, host, path, reason, attribution) stripped of terminal escapes,
/// bidi and zero-width characters (#128).
pub fn show_request(l: &Ledger, r: &wicket_store::Request) -> String {
    let clip = wicket_agent::clip;
    let age = wicket_store::now() - r.created_at;
    let mut out = format!(
        "{}  {} {}{}{}  [{}]  run {}  {}s ago{}\n    why: {}\n",
        r.id,
        clip(&r.method, 16),
        clip(&r.host, 255),
        clip(&r.path, 400),
        if r.scope_prefix { "…  (every path under it)" } else { "" },
        r.risk,
        clip(&r.run, 64),
        age,
        if r.status == "pending" { String::new() } else { format!("  ({})", clip(&r.status, 16)) },
        clip(&r.reason, 2000)
    );
    out.push_str(&format!("    agent: {}\n", clip(&identity_line(&verified_identity(l, &r.run, None)), 400)));
    for a in &r.attribution {
        out.push_str(&format!("    for: {}  (reported by the agent, unverified)\n", clip(&wicket_proxy::attribution_line(a), 240)));
    }
    out
}

/// Asks the operator at the terminal; anything but y or yes is no.
pub fn confirm(question: &str) -> Result<bool> {
    use std::io::Write;
    print!("{question} [y/N] ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
}

/// One line for terminals.
pub fn identity_line(v: &serde_json::Value) -> String {
    let g = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("?").to_string();
    if v.get("verified").and_then(|b| b.as_bool()) == Some(true) {
        let chain = v
            .get("acting_for")
            .and_then(|c| c.as_array())
            .map(|c| c.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" → "))
            .unwrap_or_default();
        format!("{} [verified]  acting for: {chain}", g("id"))
    } else {
        format!("NOT VERIFIED: {}", g("error"))
    }
}

/// The installation's identity issuer key (design §3.2). Under WICKET_HOME when that is set.
pub fn issuer_key_path() -> PathBuf {
    if let Some(d) = std::env::var_os("WICKET_HOME") {
        return PathBuf::from(d).join("identity/issuer.key");
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    home.join(".config/wicket/identity/issuer.key")
}

/// The principal behind a root run: the local unix user, which is all the PoC CLI knows, unless
/// WICKET_PRINCIPAL names one. The console sets it for the runs it starts, to the passkey-signed-in
/// operator (serve::console_principal), and records the passkey assertion over it (with the run id
/// and the manifest's digest) in the audit log; that signed record is what binds operator, run and
/// principal. The variable itself carries no more assurance than $USER: anyone who can run `wicket`
/// as this user could set either. It must be a JSON object with string `type`, `id` and `via`, or
/// it is ignored.
pub fn cli_principal() -> serde_json::Value {
    if let Some(p) = principal_from_env(std::env::var("WICKET_PRINCIPAL").ok().as_deref()) {
        return p;
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "operator".into());
    serde_json::json!({ "type": "human", "id": user, "via": "cli", "assurance": "unix-user" })
}

/// Whether the CLI's caller is root, for what only root may do: root over wicketd's socket (the
/// principal wicketd sets from the caller's peer credentials, `WICKET_PRINCIPAL`), or, without one,
/// this process's own effective uid. `$USER` is never taken for it: anyone can set that.
pub fn cli_is_root() -> bool {
    match principal_from_env(std::env::var("WICKET_PRINCIPAL").ok().as_deref()) {
        Some(p) => p["id"].as_str() == Some("root") && p["via"].as_str() == Some("cli"),
        // SAFETY: geteuid has no preconditions and can't fail.
        None => (unsafe { libc::geteuid() }) == 0,
    }
}

/// WICKET_PRINCIPAL's value, if it is a well-formed principal.
pub fn principal_from_env(v: Option<&str>) -> Option<serde_json::Value> {
    let p: serde_json::Value = serde_json::from_str(v?).ok()?;
    let is_str = |k: &str| p.get(k).is_some_and(|v| v.is_string());
    (p.is_object() && is_str("type") && is_str("id") && is_str("via")).then_some(p)
}

/// The trust domain asked for in the environment, if any. The installation's own is recorded with
/// its issuer key (`wicket identity init`); this only sets it on first use, and must match after.
pub fn trust_domain() -> Option<String> {
    std::env::var("WICKET_TRUST_DOMAIN").ok().filter(|s| !s.is_empty())
}

pub fn issuer() -> Result<wicket_identity::Issuer> {
    Ok(wicket_identity::Issuer::load(&issuer_key_path(), trust_domain().as_deref())?)
}

/// Who is deciding, for the ledger. wicketd sets WICKET_OPERATOR from the caller's peer
/// credentials for the commands it runs; without it (development mode), it is $USER, which carries
/// no assurance.
pub fn operator() -> String {
    if let Some(o) = std::env::var("WICKET_OPERATOR").ok().filter(|o| !o.is_empty()) {
        return o;
    }
    let user = std::env::var("USER").unwrap_or_else(|_| "operator".into());
    format!("{user}@cli (host break-glass)")
}
