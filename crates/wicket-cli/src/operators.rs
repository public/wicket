//! Human operators as principals (#11): an identity and an authority, under the same rules as agents.
//!
//! - **Identity.** An operator is `spiffe://<trust domain>/t/<tenant>/op/<via>/<name>`
//!   ([`wicket_identity::operator_id`]): `unix/<user>` on the CLI (the user wicketd's peer
//!   credentials name, or `$USER` without wicketd), `passkey/<name>` on the console. A run an
//!   operator starts records it in its principal (`sub`), next to how wicket knew them.
//! - **Authority.** `operators.yaml` in wicket's data directory gives each operator one; an operator
//!   it doesn't list has its `default`, and without the file every operator may decide anything,
//!   as before. A decision (approve, deny, renew) outside the decider's authority is refused and the
//!   refusal is audited, through the same [`crate::grant::decide`] agents decide through.
//!
//! ```yaml
//! default: anything            # or: nothing, or a scope
//! operators:
//!   unix/alice: anything
//!   passkey/laptop:
//!     kinds: [http]            # http, spawn, link, capacity, update, authority
//!     hosts: ["*.example.com"] # an http request's host; empty or absent: any host
//!     max_risk: R2             # the highest risk it may decide; absent: any
//!   unix/auditor: nothing      # sees requests, decides none
//! ```
//!
//! Left for later (#11): roles, several operators with their own enrolment, and two-person
//! approval for R4.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// What an operator may decide.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authority {
    /// Every decision (the default, so nothing changes until a policy says otherwise).
    Anything,
    /// No decision at all.
    Nothing,
    Scoped(Scope),
}

/// A limited authority: what kinds of request, for which hosts, up to which risk.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    /// The request kinds it may decide: `http`, `spawn`, `link`, `capacity`, `update`, and
    /// `authority` (renewing a running box's authority). Empty: none.
    #[serde(default)]
    pub kinds: Vec<String>,
    /// The hosts (`*.example.com` patterns) of the http requests it may decide. Empty: any.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// The highest risk it may decide, `R0` to `R4`. None: any.
    #[serde(default)]
    pub max_risk: Option<String>,
}

const KINDS: &[&str] = &["http", "spawn", "link", "capacity", "update", "authority"];

#[derive(Deserialize)]
#[serde(untagged)]
enum RawAuthority {
    Word(String),
    Scope(Scope),
}

impl TryFrom<RawAuthority> for Authority {
    type Error = anyhow::Error;
    fn try_from(r: RawAuthority) -> Result<Authority> {
        match r {
            RawAuthority::Word(w) if w == "anything" => Ok(Authority::Anything),
            RawAuthority::Word(w) if w == "nothing" => Ok(Authority::Nothing),
            RawAuthority::Word(w) => bail!("authority {w:?} is not one of: anything, nothing, or a scope {{kinds, hosts, max_risk}}"),
            RawAuthority::Scope(s) => {
                if let Some(k) = s.kinds.iter().find(|k| !KINDS.contains(&k.as_str())) {
                    bail!("kind {k:?} is not one of {}", KINDS.join(", "));
                }
                if let Some(r) = &s.max_risk {
                    risk_rank(r).with_context(|| format!("max_risk {r:?} is not one of R0, R1, R2, R3, R4"))?;
                }
                Ok(Authority::Scoped(s))
            }
        }
    }
}

fn risk_rank(r: &str) -> Option<i64> {
    match r {
        "R0" => Some(0),
        "R1" => Some(1),
        "R2" => Some(2),
        "R3" => Some(3),
        "R4" => Some(4),
        _ => None,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    default: Option<RawAuthority>,
    #[serde(default)]
    operators: BTreeMap<String, RawAuthority>,
}

/// Every operator's authority.
#[derive(Clone, Debug)]
pub struct Policy {
    default: Authority,
    operators: BTreeMap<String, Authority>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { default: Authority::Anything, operators: BTreeMap::new() }
    }
}

impl Policy {
    pub fn parse(s: &str) -> Result<Policy> {
        if s.trim().is_empty() {
            return Ok(Policy::default());
        }
        let f: File = serde_yaml::from_str(s)?;
        let default = f.default.map(Authority::try_from).transpose()?.unwrap_or(Authority::Anything);
        let mut operators = BTreeMap::new();
        for (k, v) in f.operators {
            let a = Authority::try_from(v).with_context(|| format!("operator {k}"))?;
            operators.insert(k, a);
        }
        Ok(Policy { default, operators })
    }

    /// The policy at `path`; every operator may decide anything when there is none. A file that
    /// doesn't parse is an error: an authority is never guessed.
    pub fn load(path: &Path) -> Result<Policy> {
        match std::fs::read_to_string(path) {
            Ok(s) => Policy::parse(&s).with_context(|| path.display().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Policy::default()),
            Err(e) => Err(anyhow::Error::from(e).context(path.display().to_string())),
        }
    }

    /// The authority of the operator `via/name` (or named by its full id).
    pub fn authority(&self, id: &str, via: &str, name: &str) -> Authority {
        let short = format!("{via}/{name}");
        self.operators.get(id).or_else(|| self.operators.get(&short)).cloned().unwrap_or_else(|| self.default.clone())
    }
}

pub fn policy_path() -> PathBuf {
    crate::data_dir().join("operators.yaml")
}

/// The installation's trust domain, as its issuer key recorded it (or as asked for on first use);
/// `local` before there is one.
pub fn trust_domain() -> String {
    let recorded = std::fs::read_to_string(crate::issuer_key_path().with_extension("trust-domain")).ok().map(|s| s.trim().to_string());
    recorded.filter(|s| !s.is_empty()).or_else(crate::trust_domain).unwrap_or_else(|| "local".into())
}

/// One operator deciding: who they are, how the ledger labels their decisions, and their authority.
#[derive(Clone, Debug)]
pub struct Operator {
    /// Its principal id.
    pub id: String,
    /// How the ledger records its decisions (`decided_by`, the audit record's `by`).
    pub label: String,
    pub authority: Authority,
}

/// What a decision is on, as an authority sees it.
#[derive(Clone, Debug)]
pub struct Asked {
    /// http, spawn, link, capacity, update or authority.
    pub kind: String,
    pub host: String,
    /// Its risk rank (0 to 4), if it has one.
    pub risk: Option<i64>,
}

impl Asked {
    pub fn of_request(r: &wicket_store::Request) -> Asked {
        Asked::of_op(&r.method, &r.host, wicket_core::RiskClass::from_name(&r.risk).map(|x| x.rank()))
    }

    pub fn of_op(method: &str, host: &str, risk: Option<i64>) -> Asked {
        let m = method.to_ascii_uppercase();
        let kind = if wicket_core::op::HTTP_METHODS.contains(&m.as_str()) { "http".to_string() } else { m.to_ascii_lowercase() };
        Asked { kind, host: host.to_string(), risk }
    }

    pub fn authority() -> Asked {
        Asked { kind: "authority".into(), host: String::new(), risk: None }
    }
}

impl Operator {
    /// An operator `via/name` of `tenant`, with the authority `policy` gives it.
    pub fn new(tenant: &str, via: &str, name: &str, label: String, policy: &Policy) -> Operator {
        let id = wicket_identity::operator_id(&trust_domain(), tenant, via, name);
        let (via, name) = (wicket_identity::id_segment(via), wicket_identity::id_segment(name));
        let authority = policy.authority(&id, &via, &name);
        Operator { id, label, authority }
    }

    /// The operator running this CLI command: the unix user wicketd's peer credentials named (or
    /// `$USER` without wicketd), with the authority `operators.yaml` gives it.
    pub fn cli(tenant: &str) -> Result<Operator> {
        let p = crate::cli_principal();
        let (via, name) = via_name(&p).unwrap_or_else(|| ("unix".into(), p["id"].as_str().unwrap_or("operator").to_string()));
        Ok(Operator::new(tenant, &via, &name, crate::operator(), &Policy::load(&policy_path())?))
    }

    /// The console's operator, signed in with passkey `name`.
    pub fn console(tenant: &str, name: &str) -> Result<Operator> {
        Ok(Operator::new(tenant, "passkey", name, format!("passkey:{name}"), &Policy::load(&policy_path())?))
    }

    /// Whether this operator may decide `a`: Err says why not.
    pub fn may_decide(&self, a: &Asked) -> std::result::Result<(), String> {
        let s = match &self.authority {
            Authority::Anything => return Ok(()),
            Authority::Nothing => return Err(format!("operator {} may decide nothing (operators.yaml)", self.id)),
            Authority::Scoped(s) => s,
        };
        if !s.kinds.iter().any(|k| k == &a.kind) {
            return Err(format!("operator {} may not decide {} requests (its kinds: {})", self.id, a.kind, s.kinds.join(", ")));
        }
        if a.kind == "http" && !s.hosts.is_empty() && !s.hosts.iter().any(|h| wicket_core::manifest::host_matches(h, &a.host)) {
            return Err(format!("operator {} may not decide requests for {} (its hosts: {})", self.id, a.host, s.hosts.join(", ")));
        }
        if let Some(max) = s.max_risk.as_deref().and_then(risk_rank) {
            match a.risk {
                Some(r) if r <= max => {}
                Some(r) => return Err(format!("operator {} may decide up to risk R{max}, and this is R{r}", self.id)),
                None if a.kind == "authority" => {}
                None => return Err(format!("operator {} may decide up to risk R{max}, and this request's risk is unknown", self.id)),
            }
        }
        Ok(())
    }
}

/// How wicket knew a human principal, as an operator's `via` and name: the CLI's unix user, or the
/// console's passkey. None for anything else (a wrapped harness's account, a trigger).
fn via_name(p: &serde_json::Value) -> Option<(String, String)> {
    if p["type"].as_str() != Some("human") {
        return None;
    }
    let id = p["id"].as_str()?;
    match p["via"].as_str()? {
        "cli" => Some(("unix".into(), id.to_string())),
        "console" => Some(("passkey".into(), id.strip_prefix("passkey:").unwrap_or(id).to_string())),
        _ => None,
    }
}

/// A root run's principal with its operator identity (#11): `sub`, the operator's principal id,
/// computed here from how wicket knew them, never taken from what was passed in.
pub fn with_identity(mut p: serde_json::Value, tenant: &str) -> serde_json::Value {
    let id = via_name(&p).map(|(via, name)| wicket_identity::operator_id(&trust_domain(), tenant, &via, &name));
    if let Some(o) = p.as_object_mut() {
        o.remove("sub");
        if let Some(id) = id {
            o.insert("sub".into(), id.into());
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(policy: &str, via: &str, name: &str) -> Operator {
        Operator::new("default", via, name, format!("{name}@test"), &Policy::parse(policy).unwrap())
    }

    fn http(host: &str, risk: i64) -> Asked {
        Asked::of_op("POST", host, Some(risk))
    }

    #[test]
    fn without_a_policy_every_operator_may_decide_anything() {
        let o = op("", "unix", "alice");
        assert_eq!(o.authority, Authority::Anything);
        assert!(o.id.ends_with("/t/default/op/unix/alice"), "{}", o.id);
        for a in [http("x.com", 4), Asked::of_op("SPAWN", "wicket.internal", Some(4)), Asked::authority()] {
            assert!(o.may_decide(&a).is_ok());
        }
    }

    #[test]
    fn a_scoped_operator_decides_only_within_its_scope() {
        let p = "default: nothing\noperators:\n  unix/bob: { kinds: [http, authority], hosts: [\"*.example.com\"], max_risk: R2 }\n  unix/alice: anything\n";
        let bob = op(p, "unix", "bob");
        assert!(bob.may_decide(&http("api.example.com", 2)).is_ok());
        assert!(bob.may_decide(&http("api.example.com", 3)).unwrap_err().contains("up to risk R2"));
        assert!(bob.may_decide(&http("example.org", 1)).unwrap_err().contains("may not decide requests for example.org"));
        assert!(bob.may_decide(&Asked::of_op("CAPACITY", "wicket.internal", Some(3))).unwrap_err().contains("capacity"));
        assert!(bob.may_decide(&Asked::authority()).is_ok());
        assert!(op(p, "unix", "alice").may_decide(&http("example.org", 4)).is_ok());
        // Not listed: the default. A passkey of the same name is another operator.
        assert!(op(p, "passkey", "alice").may_decide(&http("example.org", 0)).unwrap_err().contains("may decide nothing"));
    }

    #[test]
    fn a_policy_that_doesnt_parse_is_refused() {
        for bad in [
            "default: everything\n",
            "operators:\n  unix/x: { kinds: [root] }\n",
            "operators:\n  unix/x: { max_risk: R9 }\n",
            "default: anything\nroles: []\n",
        ] {
            assert!(Policy::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_root_runs_principal_names_its_operator() {
        let cli = with_identity(serde_json::json!({ "type": "human", "id": "alice", "via": "cli", "sub": "spiffe://forged" }), "t0");
        assert!(cli["sub"].as_str().unwrap().ends_with("/t/t0/op/unix/alice"), "{cli}");
        let console = with_identity(serde_json::json!({ "type": "human", "id": "passkey:laptop", "via": "console" }), "t0");
        assert!(console["sub"].as_str().unwrap().ends_with("/t/t0/op/passkey/laptop"), "{console}");
        let other = with_identity(serde_json::json!({ "type": "human", "id": "a@b", "via": "remote-control", "sub": "x" }), "t0");
        assert!(other.get("sub").is_none(), "{other}");
    }
}
