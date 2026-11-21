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
//!     kinds: [http]            # http, spawn, link, capacity, update, tool, name, authority, fence, policy, node
//!     hosts: ["*.example.com"] # an http request's host; empty or absent: any host
//!     max_risk: R2             # the highest risk it may decide; absent: any
//!   unix/auditor: nothing      # sees requests, decides none
//! agents:                      # what agents may decide for their descendants (#256, #50)
//!   kinds: [http]              # the request kinds (only http so far)
//!   prefix: false              # a request for every path under a prefix, and grants of one
//!   zone_wide: false           # grants (and renewals) to the asking run's whole zone
//!   git_push: false            # a git push's grant, a window rather than a number of uses (#26)
//!   unbounded: false           # grants (and renewals) with no number of uses
//! ```
//!
//! An agent decides only within its own authority whatever these say: requests from its
//! descendants, what its own zone allows by reach and its org layer doesn't refuse, ending no later
//! than its own authority, at most `MAX_AGENT_USES` uses ([`crate::grant::within_authority`]).
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
    /// The request kinds it may decide: `http`, `spawn`, `link`, `capacity`, `update`, `tool` (a
    /// driven agent's prompt before a tool call, #363), `name` (a public name, #575), `authority`
    /// (renewing a running box's authority), `fence` (releasing a run's fence from the console,
    /// #690, at R4), `policy` (applying the org policy from the console, #712, at R4), and `node`
    /// (setting a node's public addresses from the console, #575 step 4d, at R4). Empty: none.
    #[serde(default, deserialize_with = "wicket_core::yaml::null_as_default")]
    pub kinds: Vec<String>,
    /// The hosts (`*.example.com` patterns) of the http requests it may decide. Empty: any.
    #[serde(default, deserialize_with = "wicket_core::yaml::null_as_default")]
    pub hosts: Vec<String>,
    /// The highest risk it may decide, `R0` to `R4`. None: any.
    #[serde(default)]
    pub max_risk: Option<String>,
}

const KINDS: &[&str] = &["http", "spawn", "link", "capacity", "update", "tool", "name", "authority", "fence", "policy", "node"];

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

/// What agents may decide and grant for their descendants (#256, #50): rules of the policy, each
/// defaulting to what agents could do before it was one (an operator decides the rest).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct AgentRules {
    /// The request kinds an agent may decide: only `http` so far (`spawn`, `link`, `capacity`,
    /// `update` and `tool` have no agent decision path yet: an operator's).
    #[serde(deserialize_with = "wicket_core::yaml::null_as_default")]
    pub kinds: Vec<String>,
    /// A request for every path under a prefix; a grant or renewal of a prefix.
    pub prefix: bool,
    /// A grant or renewal to the asking run's whole zone, not the run alone.
    pub zone_wide: bool,
    /// A git push's grant: a window, not a number of uses (#26).
    pub git_push: bool,
    /// A grant or renewal with no number of uses.
    pub unbounded: bool,
}

impl Default for AgentRules {
    fn default() -> Self {
        AgentRules { kinds: vec!["http".into()], prefix: false, zone_wide: false, git_push: false, unbounded: false }
    }
}

/// The request kinds agents can decide at all.
const AGENT_KINDS: &[&str] = &["http"];

impl AgentRules {
    fn check(&self) -> Result<()> {
        if let Some(k) = self.kinds.iter().find(|k| !AGENT_KINDS.contains(&k.as_str())) {
            bail!("agents.kinds: {k:?} can't be decided by an agent (only {} so far)", AGENT_KINDS.join(", "));
        }
        Ok(())
    }

    /// The rules as `operators.yaml`'s `agents:` section (JSON, which YAML reads): what
    /// [`Policy::parse`] reads back as these rules. For the fuzz target (#326).
    #[doc(hidden)]
    pub fn as_policy_yaml(&self) -> String {
        format!("agents: {}\n", serde_json::to_string(self).expect("rules serialise"))
    }

    /// The rules on what an agent may grant, for [`wicket_core::authority::agent_term_refusal`]
    /// (which Kani checks, #325). The default rules lift no refusal.
    pub fn grant_rules(&self) -> wicket_core::authority::GrantRules {
        wicket_core::authority::GrantRules {
            prefix: self.prefix,
            zone_wide: self.zone_wide,
            git_push: self.git_push,
            unbounded: self.unbounded,
        }
    }

    /// Whether an agent may decide a request of this method at all.
    pub fn decides(&self, method: &str) -> bool {
        let kind = Asked::of_op(method, "", None).kind;
        self.kinds.contains(&kind)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    default: Option<RawAuthority>,
    #[serde(default)]
    agents: Option<AgentRules>,
    #[serde(default, deserialize_with = "wicket_core::yaml::null_as_default")]
    operators: BTreeMap<String, RawAuthority>,
}

/// Every operator's authority.
#[derive(Clone, Debug)]
pub struct Policy {
    default: Authority,
    operators: BTreeMap<String, Authority>,
    agents: AgentRules,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { default: Authority::Anything, operators: BTreeMap::new(), agents: AgentRules::default() }
    }
}

impl Policy {
    pub fn parse(s: &str) -> Result<Policy> {
        if s.trim().is_empty() {
            return Ok(Policy::default());
        }
        let f: File = wicket_core::yaml::from_str(s)?;
        let default = f.default.map(Authority::try_from).transpose()?.unwrap_or(Authority::Anything);
        let mut operators = BTreeMap::new();
        for (k, v) in f.operators {
            let a = Authority::try_from(v).with_context(|| format!("operator {k}"))?;
            operators.insert(k, a);
        }
        let agents = f.agents.unwrap_or_default();
        agents.check()?;
        Ok(Policy { default, operators, agents })
    }

    /// What agents may decide and grant.
    pub fn agents(&self) -> &AgentRules {
        &self.agents
    }

    /// The agents' rules from the installation's policy: the defaults when there is none, and when
    /// it doesn't load (they are the narrowest).
    pub fn agent_rules() -> AgentRules {
        Policy::load(&policy_path()).map(|p| p.agents).unwrap_or_default()
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

    /// The default rules are the ones Kani's harnesses call the default (#325): they lift no
    /// refusal, and each field maps to its own rule.
    #[test]
    fn agent_rules_map_to_the_grant_rules_kani_checks() {
        use wicket_core::authority::GrantRules;
        assert_eq!(AgentRules::default().grant_rules(), GrantRules::default());
        assert_eq!(Policy::parse("").unwrap().agents.grant_rules(), GrantRules::default(), "no agents: section");
        let one = |f: fn(&mut AgentRules)| {
            let mut r = AgentRules::default();
            f(&mut r);
            r.grant_rules()
        };
        assert_eq!(one(|r| r.prefix = true), GrantRules { prefix: true, ..GrantRules::default() });
        assert_eq!(one(|r| r.zone_wide = true), GrantRules { zone_wide: true, ..GrantRules::default() });
        assert_eq!(one(|r| r.git_push = true), GrantRules { git_push: true, ..GrantRules::default() });
        assert_eq!(one(|r| r.unbounded = true), GrantRules { unbounded: true, ..GrantRules::default() });
    }

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
            "agents:\n  kinds: [http, spawn]\n",
            "agents:\n  push: true\n",
        ] {
            assert!(Policy::parse(bad).is_err(), "{bad}");
        }
    }

    /// #256, #50: what agents may grant is the policy's `agents`, and without it (or the file)
    /// exactly what they always could: HTTP requests, one run, one path, counted, no push.
    #[test]
    fn agents_rules_default_to_what_agents_always_could() {
        let narrow = AgentRules { kinds: vec!["http".into()], prefix: false, zone_wide: false, git_push: false, unbounded: false };
        assert_eq!(Policy::default().agents(), &narrow);
        assert_eq!(Policy::parse("default: anything\n").unwrap().agents(), &narrow);
        assert_eq!(Policy::parse("agents: {}\n").unwrap().agents(), &narrow);
        let p = Policy::parse("agents:\n  prefix: true\n  git_push: true\n").unwrap();
        assert_eq!(p.agents(), &AgentRules { prefix: true, git_push: true, ..narrow.clone() });
        assert!(narrow.decides("GET") && narrow.decides("post") && !narrow.decides("SPAWN"));
        assert!(!Policy::parse("agents:\n  kinds: []\n").unwrap().agents().decides("GET"), "no kinds: decides nothing");
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
