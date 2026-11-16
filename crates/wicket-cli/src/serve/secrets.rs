//! The console's Secrets card: the vault by name, and three passkey-signed actions on it.
//!
//! - **View** (in `/api/state`, an operator's session): each secret's name, kind (a stored value or
//!   a reference to a file on the host), the hosts it may be sent to, when it was last set, and which
//!   zones (the allowlisted manifests' injections and model proxy, with each injection's host, header
//!   and format) and running runs use it; and the names manifests use that the vault doesn't have.
//!   **Never a value**, nor anything derived from one (no prefix, length or digest): the view is built
//!   from [`wicket_proxy::vault::Vault::info`], which never reads a value.
//! - **Actions** (`set_secret`, `secret_hosts`, `delete_secret`), each a signed console action like
//!   `decide`: the server builds the JSON the passkey signs at `begin` from its own reading of the
//!   vault, and at `finish` checks nothing changed in between (the secret is still there, or still
//!   absent, with the hosts it was shown with), applies it, and audits it with the signed record, by
//!   name only.
//!   - `set_secret` stores a new value or replaces one. **The value is never in the signed JSON**: the
//!     page sends a random salt and `sha256(salt || value)` at `begin`, which the passkey signs, and
//!     the value itself only in the body of `finish`, which must hash to what was signed. So the
//!     value never sits in a pending challenge, is never in a response, a log or the audit (which
//!     keeps the salted digest the passkey signed), and is zeroized once stored (as the request body
//!     it came in is). Hosts: as `wicket secret set --hosts`: those given, else the ones it had, else
//!     a harness's default model host for its default model secret.
//!   - `secret_hosts` replaces a secret's hosts, as `wicket secret hosts`: a secret is sent only to
//!     hosts it is bound to. A reference's hosts can be changed here too.
//!   - `delete_secret` removes it (a reference: only the reference), as `wicket secret rm`; the signed
//!     JSON names the zones and running runs that use it, which the page shows before signing.
//! - **References** (`wicket secret link`) name a path on the host, so making one stays CLI-only.
//! - **Unsigned** asks (`/api/secrets/*`, the endpoints a session alone might try) are refused and
//!   the refusal audited, as is a secret action whose passkey signature fails.
//!
//! Boxes using a secret read it as they always have: the proxies read the vault at each use, and
//! a node holding a copy is told to drop it when it changes, so a new value is used from the next
//! fetch.

use super::{err, str_field, Reply, State};
use http::StatusCode;
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use wicket_proxy::vault::Vault;
use zeroize::Zeroizing;

/// The longest value the console stores (bytes): an API key or token, not a file.
pub const MAX_VALUE: usize = 16 * 1024;
/// The salt the page hashes a value with: at least this many bytes, hex.
const MIN_SALT: usize = 16;
/// Why a reference can't be made here.
pub const LINK_CLI_ONLY: &str =
    "a reference names a file on the host, so it is made on the host: wicket secret link NAME --file PATH [--pointer /json/pointer]";

/// A secret action, as resolved at `begin` (never holding a value).
#[derive(Clone, Debug, PartialEq)]
pub enum Change {
    Set { name: String, replaces: bool, hosts: Vec<String>, previous_hosts: Vec<String>, value_sha256: String, salt: String },
    Hosts { name: String, hosts: Vec<String>, previous_hosts: Vec<String> },
    Delete { name: String, reference: bool, previous_hosts: Vec<String> },
}

impl Change {
    pub fn name(&self) -> &str {
        match self {
            Change::Set { name, .. } | Change::Hosts { name, .. } | Change::Delete { name, .. } => name,
        }
    }
}

fn vault(state: &State) -> Vault {
    Vault::new(state.vault_dir.clone())
}

/// A secret name as the vault takes it: letters, digits, `-` and `_`.
fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > 64 || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("a secret name is 1 to 64 letters, digits, '-' and '_'".into());
    }
    Ok(())
}

/// A name from an untrusted body, safe to audit: the name if it is one, else a marker.
pub fn audit_name(body: &Value) -> String {
    match str_field(body, "name") {
        Some(n) if check_name(n).is_ok() => n.to_string(),
        Some(_) => "(not a secret name)".into(),
        None => "(none)".into(),
    }
}

/// Hosts from a body: an array of strings, or one comma-separated string.
fn hosts_field(body: &Value) -> Result<Vec<String>, String> {
    let raw: Vec<String> = match body.get("hosts") {
        None | Some(Value::Null) => vec![],
        Some(Value::String(s)) => s.split(',').map(str::trim).filter(|h| !h.is_empty()).map(String::from).collect(),
        Some(Value::Array(a)) => {
            a.iter().map(|h| h.as_str().map(|s| s.trim().to_string()).ok_or("hosts must be strings")).collect::<Result<Vec<_>, _>>()?
        }
        Some(_) => return Err("hosts must be a list of host names".into()),
    };
    let raw: Vec<String> = raw.into_iter().filter(|h| !h.is_empty()).collect();
    if raw.len() > 64 {
        return Err("at most 64 hosts".into());
    }
    wicket_proxy::vault::normalize_hosts(&raw).map_err(|e| format!("{e:#}"))
}

/// Where a secret is used: by the allowlisted manifests (each zone's injections and model proxy),
/// keyed by secret name.
fn uses(state: &State) -> BTreeMap<String, Vec<Value>> {
    let mut out: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for (root, dir) in &state.roots {
        let Ok(rd) = std::fs::read_dir(dir) else { continue };
        let mut names: Vec<String> = rd.filter_map(|e| e.ok()).filter_map(|e| e.file_name().into_string().ok()).collect();
        names.sort();
        for name in names {
            let Ok((_, bytes)) = super::resolve_manifest(state, root, &name) else { continue };
            let Some(m) = std::str::from_utf8(&bytes).ok().and_then(|t| wicket_agent::load(t).ok()) else { continue };
            let z = &m.zone;
            for i in &z.inject {
                out.entry(i.secret.clone()).or_default().push(json!({
                    "root": root, "manifest": name, "zone": z.name, "use": "inject",
                    "host": i.host, "header": i.header, "format": i.format, "optional": i.optional,
                }));
            }
            if let Some(l) = z.llm.as_ref().filter(|l| !l.secret.is_empty()) {
                out.entry(l.secret.clone()).or_default().push(json!({
                    "root": root, "manifest": name, "zone": z.name, "use": "llm", "provider": l.provider,
                }));
            }
        }
    }
    out
}

/// The zones among `uses`, sorted and once each.
fn zones_of(uses: &[Value]) -> Vec<String> {
    uses.iter().filter_map(|u| u["zone"].as_str().map(String::from)).collect::<BTreeSet<_>>().into_iter().collect()
}

/// Running runs that use `name`: those in a zone that uses it, and those whose node was given it.
fn runs_using(state: &State, running: &[(String, String)], zones: &[String], name: &str) -> Vec<Value> {
    running
        .iter()
        .filter(|(run, zone)| {
            zones.contains(zone)
                || (crate::run::check_run_id(run).is_ok()
                    && crate::noderun::read_holdings(&state.data.join("runs").join(run))
                        .is_some_and(|h| h.secrets.iter().any(|s| s == name)))
        })
        .map(|(run, zone)| json!({ "run": run, "zone": zone }))
        .collect()
}

fn running(state: &State) -> Vec<(String, String)> {
    state.ledger().and_then(|l| Ok(l.running_policies()?)).unwrap_or_default().into_iter().map(|(r, z, _)| (r, z)).collect()
}

/// The Secrets card. Built from names, bindings and file times only: never a value.
pub fn view(state: &State) -> Value {
    let v = vault(state);
    let mut uses = uses(state);
    let running = running(state);
    let secrets: Vec<Value> = v
        .names()
        .into_iter()
        .filter_map(|n| v.info(&n))
        .map(|i| {
            let u = uses.remove(&i.name).unwrap_or_default();
            let zones = zones_of(&u);
            json!({
                "name": i.name,
                "kind": if i.reference.is_some() { "reference" } else { "value" },
                "reference": i.reference.as_ref().map(|r| json!({ "file": r.file, "pointer": r.pointer })),
                "hosts": i.hosts,
                "set_at": i.set_at,
                "used_by": u,
                "zones": zones,
                "runs": runs_using(state, &running, &zones, &i.name),
            })
        })
        .collect();
    // What manifests use that isn't in the vault: offered for setting.
    let missing: Vec<Value> = uses.into_iter().map(|(name, u)| json!({ "name": name, "zones": zones_of(&u), "used_by": u })).collect();
    json!({ "secrets": secrets, "missing": missing, "link_cli_only": LINK_CLI_ONLY, "max_value": MAX_VALUE })
}

/// Resolves a secret action at `begin` and builds the JSON the passkey signs.
pub fn prepare(state: &State, kind: &str, body: &Value) -> Result<(Change, Value), Reply> {
    let bad = |m: &str| err(StatusCode::BAD_REQUEST, m);
    // The value goes only with `finish`, so it is never kept with a pending challenge.
    if body.get("value").is_some() {
        return Err(bad("send the value with finish, never with begin: begin signs its salted sha256 (value_sha256, value_salt)"));
    }
    if body.get("file").is_some() || body.get("pointer").is_some() {
        return Err(bad(LINK_CLI_ONLY));
    }
    let name = str_field(body, "name").ok_or_else(|| bad("name required"))?;
    check_name(name).map_err(|e| bad(&e))?;
    let v = vault(state);
    let info = v.info(name);
    let previous_hosts = info.as_ref().map(|i| i.hosts.clone()).unwrap_or_default();
    let reference = info.as_ref().is_some_and(|i| i.reference.is_some());
    let u = uses(state).remove(name).unwrap_or_default();
    let zones = zones_of(&u);
    let base = |action: &str| json!({ "v": 1, "action": action, "tenant": state.tenant.0, "name": name, "zones": zones });
    match kind {
        "set_secret" => {
            if reference {
                return Err(err(
                    StatusCode::CONFLICT,
                    format!("{name} is a reference to a file on the host; replacing it with a stored value is done on the host (wicket secret rm, then wicket secret set)"),
                ));
            }
            let digest = str_field(body, "value_sha256").unwrap_or("");
            let salt = str_field(body, "value_salt").unwrap_or("");
            let hex_of = |s: &str, n: usize| {
                s.len() >= n * 2 && s.len() <= 128 && s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_hexdigit())
            };
            if digest.len() != 64 || !hex_of(digest, 32) || !hex_of(salt, MIN_SALT) {
                return Err(bad("value_sha256 (hex sha256 of salt || value) and value_salt (at least 16 random bytes, hex) are required"));
            }
            let given = hosts_field(body).map_err(|e| bad(&e))?;
            let hosts = if !given.is_empty() {
                given
            } else if !previous_hosts.is_empty() {
                previous_hosts.clone()
            } else {
                wicket_agent::harness::default_secret_hosts(name)
            };
            let mut j = base("set_secret");
            j["replaces"] = info.is_some().into();
            j["hosts"] = json!(hosts);
            j["previous_hosts"] = json!(previous_hosts);
            j["value_sha256"] = digest.to_ascii_lowercase().into();
            j["value_salt"] = salt.to_ascii_lowercase().into();
            let c = Change::Set {
                name: name.into(),
                replaces: info.is_some(),
                hosts,
                previous_hosts,
                value_sha256: digest.to_ascii_lowercase(),
                salt: salt.to_ascii_lowercase(),
            };
            Ok((c, j))
        }
        "secret_hosts" => {
            if info.is_none() {
                return Err(err(StatusCode::NOT_FOUND, format!("no secret {name}")));
            }
            let hosts = hosts_field(body).map_err(|e| bad(&e))?;
            if hosts.is_empty() {
                return Err(bad("hosts required: at least one host name, or *.domain (to send it nowhere, delete it)"));
            }
            let mut j = base("secret_hosts");
            j["kind"] = if reference { "reference" } else { "value" }.into();
            j["hosts"] = json!(hosts);
            j["previous_hosts"] = json!(previous_hosts);
            Ok((Change::Hosts { name: name.into(), hosts, previous_hosts }, j))
        }
        "delete_secret" => {
            if info.is_none() {
                return Err(err(StatusCode::NOT_FOUND, format!("no secret {name}")));
            }
            let mut j = base("delete_secret");
            j["kind"] = if reference { "reference" } else { "value" }.into();
            j["hosts"] = json!(previous_hosts);
            j["runs"] = json!(runs_using(state, &running(state), &zones, name).iter().map(|r| r["run"].clone()).collect::<Vec<_>>());
            Ok((Change::Delete { name: name.into(), reference, previous_hosts }, j))
        }
        _ => Err(bad("not a secret action")),
    }
}

/// `sha256(salt || value)`, hex: what the page signs for a value.
pub fn value_digest(salt_hex: &str, value: &str) -> String {
    let mut h = sha2::Sha256::new();
    h.update(hex::decode(salt_hex).unwrap_or_default());
    h.update(value.as_bytes());
    hex::encode(h.finalize())
}

/// Applies a signed secret action. `value` is the `finish` body's, for `set_secret` only. Returns
/// what to tell the operator and the audit record's kind and body (names and hosts only).
pub fn apply(state: &State, c: &Change, value: Option<Zeroizing<String>>) -> anyhow::Result<(String, &'static str, Value)> {
    let v = vault(state);
    let info = v.info(c.name());
    let changed = |name: &str| anyhow::anyhow!("secret {name} changed after you were shown it; look again and sign again");
    match c {
        Change::Set { name, replaces, hosts, previous_hosts, value_sha256, salt } => {
            let Some(value) = value else { anyhow::bail!("the value is required with finish (it never goes with begin)") };
            if value_digest(salt, &value) != *value_sha256 {
                anyhow::bail!("the value sent is not the one you signed for; nothing was stored");
            }
            if value.trim().is_empty() {
                anyhow::bail!("empty value; nothing was stored");
            }
            if value.len() > MAX_VALUE {
                anyhow::bail!("the value is over {MAX_VALUE} bytes; nothing was stored");
            }
            // It goes into one header: no line breaks or other control characters.
            if value.trim().chars().any(|ch| ch.is_control()) {
                anyhow::bail!("the value has a line break or another control character; nothing was stored");
            }
            if info.is_some() != *replaces || info.as_ref().is_some_and(|i| i.reference.is_some() || i.hosts != *previous_hosts) {
                return Err(changed(name));
            }
            v.set(name, &value)?;
            drop(value);
            if !hosts.is_empty() && hosts != previous_hosts {
                v.set_hosts(name, hosts)?;
            }
            let whither = if hosts.is_empty() {
                "bound to no hosts, so it is sent nowhere until you bind it".to_string()
            } else {
                format!("sent only to {}", hosts.join(", "))
            };
            let verb = if *replaces { "replaced the value of" } else { "stored" };
            Ok((
                format!("{verb} secret {name}; {whither}; running boxes use the new value from their next request"),
                "secret.set",
                json!({ "action": "set_secret", "name": name, "replaced": replaces, "hosts": hosts, "previous_hosts": previous_hosts }),
            ))
        }
        Change::Hosts { name, hosts, previous_hosts } => {
            if info.as_ref().is_none_or(|i| i.hosts != *previous_hosts) {
                return Err(changed(name));
            }
            v.set_hosts(name, hosts)?;
            Ok((
                format!("secret {name}: sent only to {}", hosts.join(", ")),
                "secret.hosts",
                json!({ "action": "secret_hosts", "name": name, "hosts": hosts, "previous_hosts": previous_hosts }),
            ))
        }
        Change::Delete { name, reference, previous_hosts } => {
            if info.as_ref().is_none_or(|i| i.reference.is_some() != *reference || i.hosts != *previous_hosts) {
                return Err(changed(name));
            }
            v.remove(name)?;
            let what = if *reference { "reference" } else { "secret" };
            Ok((
                format!("{what} {name} removed; boxes using it are refused it from their next request"),
                "secret.removed",
                json!({ "action": "delete_secret", "name": name, "reference": reference, "hosts": previous_hosts }),
            ))
        }
    }
}

/// `/api/secrets/*` with a session alone: every change to a secret is a signed action, so these are
/// refused, and the refusal audited (by name; never a value, if one was sent).
pub fn unsigned(state: &State, cred: &str, path: &str, body: &Value) -> Reply {
    if let Ok(l) = state.ledger() {
        let _ = l.audit(
            &state.tenant,
            None,
            "secret.refused",
            &json!({ "credential": cred, "path": path, "name": audit_name(body), "reason": "unsigned: a secret changes only with a passkey signature" }),
        );
    }
    err(
        StatusCode::FORBIDDEN,
        "changing a secret is a signed action: sign it with your passkey (action set_secret, secret_hosts or delete_secret)",
    )
}
