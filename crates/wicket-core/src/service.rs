//! Per-node services (#579 step 3): a program that runs on every matching node, which the boxes on
//! that node use through a link (`zone.uses`). A pull-through cache (npm, an OCI registry mirror) is
//! the example: one instance per node and tenant, fetching under its own reach.
//!
//! **Using a service is having its reach.** A box that uses an npm cache can, through it, make the
//! cache fetch whatever the box names on the cache's upstream: package names are a channel out. So a
//! box may use a service only if its own authority covers the service's reach (the link's subset
//! rule, [`crate::link`]), or a human approves that link; and a spawned box may use only the services
//! its parent may ([`crate::subset::unapprovable`]). Nothing a service fetches is more than its users
//! could have fetched themselves.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A manifest's `service:`: what makes a program a per-node service.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
    /// One instance on every node that matches `node_selector` (the only kind there is so far).
    #[serde(default = "yes")]
    pub per_node: bool,
    /// Labels a node must have to run it (#579 step 1's labels). Empty: every node.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty", deserialize_with = "crate::yaml::null_as_default")]
    pub node_selector: BTreeMap<String, String>,
    /// One instance per tenant using it on a node (the default), or one shared by every tenant.
    #[serde(default)]
    pub tenancy: Tenancy,
    /// That the service serves only public content, so a shared instance leaks nothing between
    /// tenants but what each asked for. Declared by the operator who installs the service; required
    /// for `tenancy: shared`. No agent can set it: services are installed, not spawned.
    #[serde(default)]
    pub public_only: bool,
    /// The port its users connect to (`<name>.wicket.internal:<port>`).
    pub port: u16,
    /// Environment its users get, `{host}` and `{port}` replaced: what points their tools at it
    /// (`npm_config_registry: http://{host}:{port}/`). Only names wicket doesn't control.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty", deserialize_with = "crate::yaml::null_as_default")]
    pub env: BTreeMap<String, String>,
    /// What happens to its volumes when its node is released: `drop` (a cache) or `keep`.
    #[serde(default)]
    pub drain: Drain,
}

fn yes() -> bool {
    true
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tenancy {
    #[default]
    PerTenant,
    Shared,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Drain {
    #[default]
    Drop,
    Keep,
}

impl ServiceSpec {
    pub fn check(&self) -> Result<(), String> {
        if !self.per_node {
            return Err("service.per_node: only per-node services exist so far".into());
        }
        if self.tenancy == Tenancy::Shared && !self.public_only {
            return Err("service.tenancy: shared needs public_only: true, declared by whoever installs the service: \
                        a shared instance would otherwise carry one tenant's content to another"
                .into());
        }
        if self.port == 0 {
            return Err("service.port: the port its users connect to".into());
        }
        for (k, v) in &self.node_selector {
            crate::placement::check_key(k).map_err(|e| format!("service.node_selector: {e}"))?;
            crate::placement::check_value(v).map_err(|e| format!("service.node_selector.{k}: {e}"))?;
        }
        for k in self.env.keys() {
            let ok =
                !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !k.starts_with(|c: char| c.is_ascii_digit());
            if !ok || reserved_env(k) {
                return Err(format!("service.env: {k} is not a variable a service may set for its users"));
            }
        }
        Ok(())
    }

    /// Its users' environment: `env` with `{host}` and `{port}` filled in.
    pub fn user_env(&self, name: &str) -> BTreeMap<String, String> {
        let host = format!("{name}.{}", crate::link::DOMAIN);
        self.env.iter().map(|(k, v)| (k.clone(), v.replace("{host}", &host).replace("{port}", &self.port.to_string()))).collect()
    }
}

/// Variables a service may not set for its users: every one a manifest's `agent.env` may not
/// (`manifest::RESERVED_ENV_PREFIXES`: wicket's, the model's, proxies, TLS and CA bundles, Node's
/// and curl's, MCP's, git's TLS), and the loader's, the CA bundles other tools read, and the
/// account's own. Compared ignoring case.
fn reserved_env(k: &str) -> bool {
    let k = k.to_ascii_uppercase();
    crate::manifest::RESERVED_ENV_PREFIXES.iter().any(|p| k.starts_with(p))
        || k.ends_with("_PROXY")
        || k.starts_with("LD_")
        || k.contains("CA_BUNDLE")
        || k.contains("CA_CERT")
        || k.ends_with("_CERT")
        || k.ends_with("_CERTS")
        || k.starts_with("PYTHON")
        || k.starts_with("CARGO_HTTP")
        || ["HOME", "PATH", "USER", "SHELL", "LOGNAME", "TMPDIR", "BASH_ENV", "ENV"].contains(&k.as_str())
}

/// A service's name, as `zone.uses` names it and its users' host name (`<name>.wicket.internal`)
/// carries it: lowercase letters, digits and `-`, at most 40.
pub fn check_name(n: &str) -> Result<(), String> {
    let ok = !n.is_empty()
        && n != "wicket"
        && n.len() <= 40
        && n.starts_with(|c: char| c.is_ascii_lowercase())
        && !n.ends_with('-')
        && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if ok {
        Ok(())
    } else {
        Err(format!("{n:?} is not a service name: lowercase letters, digits and -, starting with a letter, at most 40"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(y: &str) -> Result<ServiceSpec, String> {
        let s: ServiceSpec = crate::yaml::from_str(y).map_err(|e| e.to_string())?;
        s.check().map(|_| s)
    }

    #[test]
    fn a_service_is_per_tenant_unless_its_installer_says_public_only() {
        let s = spec("port: 4873\nenv: { npm_config_registry: 'http://{host}:{port}/' }").unwrap();
        assert_eq!((s.tenancy, s.drain, s.per_node), (Tenancy::PerTenant, Drain::Drop, true));
        assert_eq!(s.user_env("npm-cache")["npm_config_registry"], "http://npm-cache.wicket.internal:4873/");
        assert!(spec("port: 4873\ntenancy: shared").unwrap_err().contains("public_only"));
        assert_eq!(spec("port: 4873\ntenancy: shared\npublic_only: true").unwrap().tenancy, Tenancy::Shared);
        assert!(spec("port: 0").is_err());
        assert!(spec("port: 1\nper_node: false").is_err());
        for bad in [
            "HTTPS_PROXY",
            "https_proxy",
            "WICKET_X",
            "SSL_CERT_FILE",
            "PATH",
            "1X",
            "A-B",
            "NODE_OPTIONS",
            "node_tls_reject_unauthorized",
            "CLAUDE_X",
            "MCP_X",
            "GIT_SSL_NO_VERIFY",
            "CURL_CA_BUNDLE",
            "USER",
            "LD_PRELOAD",
            "REQUESTS_CA_BUNDLE",
            "PIP_CERT",
            "PYTHONPATH",
        ] {
            assert!(spec(&format!("port: 1\nenv: {{ {bad}: x }}")).is_err(), "{bad}");
        }
        assert!(spec("port: 1\nnode_selector: { Bad: x }").is_err());
        assert!(spec("port: 1\nunknown: x").is_err(), "deny_unknown_fields");
    }

    #[test]
    fn service_names() {
        for ok in ["npm-cache", "oci-mirror", "a", "crates2"] {
            assert!(check_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "Npm", "-a", "a-", "a.b", "a_b", "1a", "wicket", &"a".repeat(41)] {
            assert!(check_name(bad).is_err(), "{bad}");
        }
    }
}
