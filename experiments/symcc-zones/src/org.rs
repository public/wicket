//! Architecture A's main SymCC use: a CI diff of two versions of a hand-written org policy.

use crate::{median, ms, new_solver};
use anyhow::{anyhow, Result};
use cedar_policy::{PolicySet, Schema};
use cedar_policy_symcc::CompiledPolicySet;
use std::str::FromStr;
use std::time::Instant;

const SCHEMA: &str = r#"
entity Group;
entity Tenant;
entity Human in [Group] { tenant: Tenant };
entity Zone in [Zone] { tenant: Tenant, owner: Human };
entity Agent { tenant: Tenant, zone: Zone };
entity Image { trusted: Bool, tenant: Tenant };
action "approve" appliesTo { principal: [Human], resource: [Zone], context: { risk: Long, requester: Human } };
action "inspect" appliesTo { principal: [Human, Agent], resource: [Zone] };
action "operate" appliesTo { principal: [Human], resource: [Zone] };
action "use_image" appliesTo { principal: [Agent], resource: [Image] };
action "grant_escalation" appliesTo { principal: [Agent], resource: [Zone], context: { risk: Long } };
"#;

const TENANCY: &str = r#"
@id("tenant-human") forbid(principal is Human, action, resource is Zone) unless { principal.tenant == resource.tenant };
@id("tenant-agent") forbid(principal is Agent, action, resource is Zone) unless { principal.tenant == resource.tenant };
@id("tenant-image") forbid(principal is Agent, action, resource is Image) unless { principal.tenant == resource.tenant };
"#;

const V1: &str = r#"
@id("owner-approves") permit(principal, action == Action::"approve", resource) when { resource.owner == principal && context.risk <= 3 };
@id("approvers-approve") permit(principal in Group::"approvers", action == Action::"approve", resource) when { context.risk <= 4 };
@id("no-self-approval") forbid(principal, action == Action::"approve", resource) when { context.requester == principal };
@id("owner-inspects") permit(principal is Human, action == Action::"inspect", resource) when { resource.owner == principal };
@id("operators-inspect") permit(principal in Group::"operators", action == Action::"inspect", resource);
@id("agents-inspect-descendants") permit(principal is Agent, action == Action::"inspect", resource) when { resource in principal.zone && resource != principal.zone };
@id("operators-operate") permit(principal in Group::"operators", action == Action::"operate", resource);
@id("trusted-images") permit(principal, action == Action::"use_image", resource) when { resource.trusted };
@id("agents-grant-low-risk") permit(principal, action == Action::"grant_escalation", resource) when { resource in principal.zone && context.risk <= 2 };
"#;

// A plausible PR: lets owners approve R4, drops agent inspection, and "simplifies" the
// self-approval rule in a way that quietly allows self-approval at risk 0-1.
const V2: &str = r#"
@id("owner-approves") permit(principal, action == Action::"approve", resource) when { resource.owner == principal && context.risk <= 4 };
@id("approvers-approve") permit(principal in Group::"approvers", action == Action::"approve", resource) when { context.risk <= 4 };
@id("no-self-approval") forbid(principal, action == Action::"approve", resource) when { context.requester == principal && context.risk >= 2 };
@id("owner-inspects") permit(principal is Human, action == Action::"inspect", resource) when { resource.owner == principal };
@id("operators-inspect") permit(principal in Group::"operators", action == Action::"inspect", resource);
@id("operators-operate") permit(principal in Group::"operators", action == Action::"operate", resource);
@id("trusted-images") permit(principal, action == Action::"use_image", resource) when { resource.trusted };
@id("agents-grant-low-risk") permit(principal, action == Action::"grant_escalation", resource) when { resource in principal.zone && context.risk <= 2 };
"#;

// A refactor of V1 that should change nothing.
const V3: &str = r#"
@id("approve") permit(principal, action == Action::"approve", resource) when { (resource.owner == principal && context.risk <= 3) || (principal in Group::"approvers" && context.risk <= 4) };
@id("no-self-approval") forbid(principal, action == Action::"approve", resource) when { context.requester == principal };
@id("inspect-human") permit(principal is Human, action == Action::"inspect", resource) when { resource.owner == principal || principal in Group::"operators" };
@id("inspect-agent") permit(principal is Agent, action == Action::"inspect", resource) when { resource in principal.zone && resource != principal.zone };
@id("operators-operate") permit(principal in Group::"operators", action == Action::"operate", resource);
@id("trusted-images") permit(principal, action == Action::"use_image", resource) when { resource.trusted == true };
@id("agents-grant-low-risk") permit(principal, action == Action::"grant_escalation", resource) when { context.risk < 3 && resource in principal.zone };
"#;

fn ps(body: &str) -> Result<PolicySet> {
    PolicySet::from_str(&format!("{TENANCY}{body}")).map_err(|e| anyhow!("{e:?}"))
}

pub async fn run(runs: usize) -> Result<()> {
    let (schema, _) = Schema::from_cedarschema_str(SCHEMA)?;
    let (v1, v2, v3) = (ps(V1)?, ps(V2)?, ps(V3)?);
    let mut solver = new_solver()?;
    println!("## A: org policy diff in CI (12 policies, 5 actions, 6 request environments)\n");
    println!("| question | request env | answer | median ms |");
    println!("|---|---|---|---|");
    let mut cexs = vec![];
    for env in schema.request_envs() {
        let label = format!("{} {} {}", env.principal(), env.action().id().unescaped(), env.resource());
        let c1 = CompiledPolicySet::compile(&v1, &env, &schema)?;
        let c2 = CompiledPolicySet::compile(&v2, &env, &schema)?;
        let c3 = CompiledPolicySet::compile(&v3, &env, &schema)?;
        for (q, a, b, equiv) in [("v2 no more permissive than v1 (v2 ⇒ v1)", &c2, &c1, false), ("v2 no less permissive than v1 (v1 ⇒ v2)", &c1, &c2, false), ("refactor v3 ≡ v1", &c3, &c1, true)] {
            let mut t = vec![];
            let mut ans = None;
            for _ in 0..runs {
                let t0 = Instant::now();
                ans = if equiv { solver.check_equivalent_with_counterexample_opt(a, b).await? } else { solver.check_implies_with_counterexample_opt(a, b).await? };
                t.push(ms(t0.elapsed()));
            }
            println!("| {q} | {label} | {} | {:.0} |", if ans.is_some() { "no: counterexample" } else { "yes" }, median(t));
            if let Some(e) = ans {
                // Replay the counterexample concretely against both versions.
                let auth = cedar_policy::Authorizer::new();
                let (pa, pb) = if equiv { (&v3, &v1) } else if std::ptr::eq(a, &c2) { (&v2, &v1) } else { (&v1, &v2) };
                let ra = auth.is_authorized(&e.request, pa, &e.entities);
                let rb = auth.is_authorized(&e.request, pb, &e.entities);
                let why = |r: &cedar_policy::Response, ps: &PolicySet| {
                    let ids: Vec<String> = r.diagnostics().reason().map(|p| ps.policy(p).and_then(|x| x.annotation("id").map(String::from)).unwrap_or(p.to_string())).collect();
                    let errs = r.diagnostics().errors().count();
                    format!("{:?} by {:?}{}", r.decision(), ids, if errs > 0 { format!(", {errs} policy error(s)") } else { String::new() })
                };
                cexs.push(format!(
                    "{q}, {label}: {} entities in the synthesised store; replay: first set {}, second set {}\n```\n{e}\n```",
                    e.entities.iter().count(),
                    why(&ra, pa),
                    why(&rb, pb)
                ));
            }
        }
    }
    // Compile time for the whole set, all envs.
    let t0 = Instant::now();
    for env in schema.request_envs() {
        let _ = CompiledPolicySet::compile(&v1, &env, &schema)?;
    }
    println!("\nSymCC compile of v1 for all envs: {:.1} ms\n", ms(t0.elapsed()));
    for c in cexs {
        println!("{c}\n");
    }
    Ok(())
}
