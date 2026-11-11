//! A wicket zone (plus the parts of a spawn request that aren't in the zone) to static Cedar
//! policies, one small policy set per Cedar action ("request environment").

use crate::glob::{cedar_str, glob_expr, Mode};
use wicket_core::manifest::{ReachRule, UnlistedHosts, ZoneSpec};
use wicket_core::subset::parse_bytes;
use wicket_core::Isolation;

pub const HTTP: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
pub const OTHER: &[&str] = &["run_with", "start_image", "accept_message", "inject", "use_model", "ask_unlisted"];

pub fn schema_text() -> String {
    SCHEMA.replace("entity Url { host: String, path: String };", &crate::seg::url_entity_decl())
}

const SCHEMA: &str = r#"
entity Agent;
entity Url { host: String, path: String };
entity Image;
entity Zone;
entity Secret;
entity Route;
action "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS" appliesTo {
  principal: [Agent], resource: [Url], context: { dangerous: Bool }
};
action "run_with" appliesTo {
  principal: [Agent], resource: [Zone],
  context: { memory_mb: Long, millicpus: Long, pids: Long, timeout_s: Long, isolation: Long, children: Long }
};
action "start_image" appliesTo { principal: [Agent], resource: [Image] };
action "accept_message" appliesTo { principal: [Agent], resource: [Zone] };
action "inject" appliesTo {
  principal: [Agent], resource: [Secret], context: { host: String, header: String, format: String }
};
action "use_model" appliesTo {
  principal: [Agent], resource: [Route], context: { requests: Long, output_tokens: Long, server_tools: Bool }
};
action "ask_unlisted" appliesTo { principal: [Agent], resource: [Zone] };
"#;

/// A policy plus where it came from (for explanations).
#[derive(Clone, Debug)]
pub struct Pol {
    pub id: String,
    pub text: String,
}

/// The non-zone half of a spawn: what the child asks, or what the parent has left.
#[derive(Clone, Debug)]
pub struct Extras {
    /// Images that may be started (child: its image plus zone.images; parent: Bounds.images).
    pub images: Vec<String>,
    /// Zones whose messages are accepted (parent: also itself).
    pub accept_from: Vec<String>,
    /// Max children (child: ask.max_children; parent: child_slots - 1).
    pub children: i64,
    /// Seconds of run time (child: its timeout; parent: time remaining).
    pub timeout_s: i64,
    /// Model requests / output tokens (child: its llm; parent: what is left).
    pub llm_budget: Option<(u64, u64)>,
}

pub struct Compiled {
    /// action name -> policies
    pub sets: Vec<(String, Vec<Pol>)>,
    /// Whether every glob compiled exactly in this mode.
    pub exact: bool,
}

pub fn host_expr(h: &str) -> String {
    let h = h.to_ascii_lowercase();
    match h.strip_prefix("*.") {
        Some(sfx) => format!("(resource.host like {} && resource.host != {})", like_lit(&format!("*.{sfx}"), 1), cedar_str(&format!(".{sfx}"))),
        None => format!("resource.host == {}", cedar_str(&h)),
    }
}

/// A like-pattern literal whose first `n_wild` characters `*` are wildcards (rest literal).
fn like_lit(p: &str, n_wild: usize) -> String {
    let mut s = String::new();
    let mut left = n_wild;
    for c in p.chars() {
        match c {
            '*' if left > 0 => {
                left -= 1;
                s.push('*')
            }
            '*' => s.push_str("\\*"),
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            c => s.push(c),
        }
    }
    format!("\"{s}\"")
}

fn paths_expr(paths: &[String], mode: Mode, exact: &mut bool) -> String {
    let parts: Vec<String> = paths
        .iter()
        .map(|p| {
            if crate::seg::on() {
                return crate::seg::glob_expr(p, mode, exact);
            }
            let g = glob_expr("resource.path", p, mode);
            *exact &= g.exact;
            g.expr
        })
        .collect();
    if parts.len() == 1 {
        parts.into_iter().next().unwrap()
    } else {
        format!("({})", parts.join(" || "))
    }
}

fn rule_match(r: &ReachRule, mode: Mode, exact: &mut bool) -> String {
    format!("{} && {}", host_expr(&r.host), paths_expr(&r.paths, mode, exact))
}

/// Requests wicket's proxy would never evaluate (non-canonical path or host), and hosts wicket
/// never lets a sandbox reach. Shared by every zone, so analyses only range over real requests.
pub fn envelope() -> Vec<Pol> {
    let p = "resource.path";
    let h = "resource.host";
    let path_bad = [
        format!("!({p} like \"/*\")"),
        format!("{p} like \"*//*\""),
        format!("{p} like \"*/./*\""),
        format!("{p} like \"*/../*\""),
        format!("{p} like \"*/.\""),
        format!("{p} like \"*/..\""),
        format!("{p} like \"*?*\""),
        format!("{p} like \"*%2f*\""),
        format!("{p} like \"*%2F*\""),
        format!("{p} like \"*%5c*\""),
        format!("{p} like \"*%5C*\""),
        format!("{p} like \"*%2e*\""),
        format!("{p} like \"*%2E*\""),
        format!("{p} like \"*%00*\""),
        format!("{p} like \"*%25*\""),
        format!("{p} like \"*\\\\*\""),
    ];
    let host_bad = [
        format!("{h} == \"\""),
        format!("{h} like \".*\""),
        format!("{h} like \"*.\""),
        format!("{h} like \"*..*\""),
        format!("{h} like \"*/*\""),
        format!("{h} like \"*:*\""),
        format!("{h} like \"*\\**\""),
        format!("{h} like \"* *\""),
        format!("{h} == \"localhost\""),
        format!("{h} like \"*.localhost\""),
        format!("{h} == \"metadata\""),
        format!("{h} == \"metadata.google.internal\""),
        format!("{h} == \"169.254.169.254\""),
        format!("{h} == \"100.100.100.200\""),
    ];
    let path_bad: Vec<String> = if crate::seg::on() { crate::seg::envelope_conditions() } else { path_bad.to_vec() };
    vec![
        Pol { id: "envelope-path".into(), text: format!("forbid(principal, action, resource) when {{ {} }};", path_bad.join(" || ")) },
        Pol { id: "envelope-host".into(), text: format!("forbid(principal, action, resource) when {{ {} }};", host_bad.join(" || ")) },
    ]
}

fn forbids(z: &ZoneSpec, mode: Mode, exact: &mut bool) -> Vec<Pol> {
    // A forbid narrows what is allowed, so it is approximated in the opposite direction.
    z.forbid
        .iter()
        .enumerate()
        .map(|(k, f)| Pol {
            id: format!("forbid{k}"),
            text: format!("forbid(principal, action, resource) when {{ {} && {} }};", host_expr(&f.host), paths_expr(&f.paths, mode.flip(), exact)),
        })
        .collect()
}

/// The HTTP part of a zone for one method: what `op::evaluate` returns `AllowByReach` for.
pub fn http_policies(z: &ZoneSpec, method: &str, mode: Mode, exact: &mut bool, only_rule: Option<usize>) -> Vec<Pol> {
    let mut out = vec![];
    let rules: Vec<(usize, &ReachRule)> = z.reach.iter().enumerate().filter(|(_, r)| r.methods.iter().any(|m| m.eq_ignore_ascii_case(method))).collect();
    for (pos, (i, r)) in rules.iter().enumerate() {
        if only_rule.is_some_and(|o| o != *i) {
            continue;
        }
        let m = rule_match(r, mode, exact);
        let danger = if r.allow_dangerous {
            // evaluate() stops at the first matching rule: a dangerous request is allowed by this
            // rule only if no earlier rule (without allow_dangerous) matched first.
            let earlier: Vec<String> = rules[..pos].iter().map(|(_, q)| format!("!({})", rule_match(q, mode.flip(), exact))).collect();
            if earlier.is_empty() {
                "true".to_string()
            } else {
                format!("(!context.dangerous || ({}))", earlier.join(" && "))
            }
        } else {
            "!context.dangerous".to_string()
        };
        out.push(Pol { id: format!("reach{i}"), text: format!("permit(principal, action == Action::{}, resource) when {{ {m} && {danger} }};", cedar_str(method)) });
    }
    out.extend(forbids(z, mode, exact));
    out.extend(envelope());
    out
}

/// What isn't forbidden (so may at least be asked for): `permit` everything, minus forbids.
pub fn not_forbidden_policies(z: &ZoneSpec, method: &str, mode: Mode, exact: &mut bool) -> Vec<Pol> {
    let mut out = vec![Pol { id: "anything".into(), text: format!("permit(principal, action == Action::{}, resource);", cedar_str(method)) }];
    out.extend(forbids(z, mode, exact));
    out.extend(envelope());
    out
}

fn isolation_level(i: Isolation) -> i64 {
    match i {
        Isolation::Runc => 1,
        Isolation::Gvisor => 2,
    }
}

fn eq_any(var: &str, ty: &str, ids: &[String]) -> Option<String> {
    if ids.is_empty() {
        return None;
    }
    Some(ids.iter().map(|i| format!("{var} == {ty}::{}", cedar_str(i))).collect::<Vec<_>>().join(" || "))
}

pub fn other_policies(z: &ZoneSpec, x: &Extras, action: &str) -> Vec<Pol> {
    let a = format!("action == Action::{}", cedar_str(action));
    let p = |id: &str, cond: String| Pol { id: id.into(), text: format!("permit(principal, {a}, resource) when {{ {cond} }};") };
    match action {
        "run_with" => {
            let mem = parse_bytes(&z.limits.memory).map(|b| (b >> 20) as i64).unwrap_or(0);
            let cpus = (z.limits.cpus * 1000.0).round() as i64;
            vec![p(
                "limits",
                format!(
                    "context.memory_mb <= {mem} && context.millicpus <= {cpus} && context.pids <= {} && context.timeout_s <= {} && context.isolation >= {} && context.children <= {}",
                    z.limits.pids,
                    x.timeout_s,
                    isolation_level(z.isolation),
                    x.children
                ),
            )]
        }
        "start_image" => eq_any("resource", "Image", &x.images).map(|c| vec![p("images", c)]).unwrap_or_default(),
        "accept_message" => eq_any("resource", "Zone", &x.accept_from).map(|c| vec![p("accept_from", c)]).unwrap_or_default(),
        "inject" => z
            .inject
            .iter()
            .enumerate()
            .map(|(k, i)| {
                p(
                    &format!("inject{k}"),
                    format!(
                        "resource == Secret::{} && context.host == {} && context.header == {} && context.format == {}",
                        cedar_str(&i.secret),
                        cedar_str(&i.host),
                        cedar_str(&i.header),
                        cedar_str(&i.format)
                    ),
                )
            })
            .collect(),
        "use_model" => match (&z.llm, x.llm_budget) {
            (Some(l), Some((r, t))) => {
                let route = format!("{}|{}|{}", l.provider, l.secret, l.upstream);
                let tools = if l.allow_server_tools { "true" } else { "!context.server_tools" };
                vec![p("llm", format!("resource == Route::{} && context.requests <= {r} && context.output_tokens <= {t} && {tools}", cedar_str(&route)))]
            }
            _ => vec![],
        },
        "ask_unlisted" => {
            if z.unlisted_hosts == UnlistedHosts::Escalate {
                vec![p("unlisted_escalate", "true".into())]
            } else {
                vec![]
            }
        }
        _ => unreachable!("{action}"),
    }
}

pub fn compile_zone(z: &ZoneSpec, x: &Extras, mode: Mode) -> Compiled {
    let mut exact = true;
    let mut sets = vec![];
    for m in HTTP {
        sets.push((m.to_string(), http_policies(z, m, mode, &mut exact, None)));
    }
    for a in OTHER {
        sets.push((a.to_string(), other_policies(z, x, a)));
    }
    Compiled { sets, exact }
}

pub fn compile_not_forbidden(z: &ZoneSpec, mode: Mode) -> Compiled {
    let mut exact = true;
    let sets = HTTP.iter().map(|m| (m.to_string(), not_forbidden_policies(z, m, mode, &mut exact))).collect();
    Compiled { sets, exact }
}
