//! The Cedar schema every wicket policy is validated against (strictly), and what the node knows of
//! each request at the edge.
//!
//! - **Principal:** the box (`Box`), a member of its zone (`Zone`), which may be in groups (`Group`,
//!   from the org's entities). Its attributes are known when its token is minted, so conditions on
//!   them are decided then (folded away), never at the edge.
//! - **HTTP** (one action per method): the resource is the URL, `host` and `path`, and
//!   `path_matches` / `path_matches_any_case`, the wicket path globs the path matches (`*` within
//!   a segment, `**` across), case-sensitively or ignoring ASCII case. `context.risk` is
//!   wicket-core's risk rank.
//! - **spawn:** the image started, with the spawn's isolation and resource limits.
//! - **message:** the sending box's zone.
//! - **inject:** the credential injected, with the host and header it goes in.

/// The schema, in Cedar's human-readable format.
pub const SCHEMA: &str = r#"
entity Group in [Group];
entity Zone in [Group];
entity Box in [Zone] = {
  "zone": String,
  "tenant": String,
  "principal": String,
  "depth": Long,
};
entity Url = {
  "host": String,
  "path": String,
  "path_matches": Set<String>,
  "path_matches_any_case": Set<String>,
};
entity Image;
entity Secret;

type Http = { "risk": Long };
action "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS" appliesTo {
  principal: [Box], resource: [Url], context: Http
};
action "spawn" appliesTo {
  principal: [Box], resource: [Image],
  context: { "isolation": Long, "memory": Long, "cpus_milli": Long, "pids": Long, "timeout_s": Long }
};
action "message" appliesTo { principal: [Box], resource: [Zone], context: {} };
action "inject" appliesTo {
  principal: [Box], resource: [Secret], context: { "host": String, "header": String }
};
"#;

/// The HTTP methods wicket's policies know (one Cedar action each).
pub const METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

pub fn schema() -> cedar_policy::Schema {
    SCHEMA.parse().expect("wicket's Cedar schema parses")
}
