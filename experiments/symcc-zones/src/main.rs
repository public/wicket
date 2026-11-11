mod cases;
mod compile;
mod glob;
mod oracle;
mod org;
mod seg;

use anyhow::{anyhow, Result};
use cedar_policy::{Authorizer, Context, Decision, Entities, Entity, EntityId, EntityUid, EvalResult, Policy, PolicyId, PolicySet, Request, RequestEnv, RestrictedExpression, Schema};
use cedar_policy_symcc::solver::LocalSolver;
use cedar_policy_symcc::{CedarSymCompiler, CompiledPolicySet, Env};
use compile::{Compiled, Extras, Pol, HTTP};
use glob::Mode;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use wicket_core::subset;
use wicket_core::ZoneSpec;

pub type Solver = CedarSymCompiler<LocalSolver>;

/// cvc5 with a per-query time limit (ms) from TLIMIT_MS. SymCC's `LocalSolver::cvc5()` passes
/// `--tlimit=60000`, which cvc5 applies to the whole process lifetime: a reused solver aborts 60 s
/// after it started, idle or not.
pub fn new_solver() -> Result<Solver> {
    let t = std::env::var("TLIMIT_MS").unwrap_or_else(|_| "60000".into());
    Ok(CedarSymCompiler::new(LocalSolver::cvc5_with_args([format!("--tlimit-per={t}")])?)?)
}

pub fn pset(pols: &[Pol]) -> Result<PolicySet> {
    let mut ps = PolicySet::new();
    for p in pols {
        ps.add(Policy::parse(Some(PolicyId::new(&p.id)), &p.text).map_err(|e| anyhow!("{}: {e}\n{}", p.id, p.text))?)?;
    }
    Ok(ps)
}

pub fn envs(schema: &Schema) -> HashMap<String, RequestEnv> {
    schema.request_envs().map(|e| (e.action().id().unescaped().to_string(), e)).collect()
}

/// Peak RSS (KiB) of live cvc5 children, sampled.
fn cvc5_hwm_kib() -> u64 {
    let mut max = 0;
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else { return 0 };
    for t in tasks.flatten() {
        let Ok(kids) = std::fs::read_to_string(t.path().join("children")) else { continue };
        for pid in kids.split_whitespace() {
            if let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
                if let Some(l) = s.lines().find(|l| l.starts_with("VmHWM:")) {
                    let kb: u64 = l.split_whitespace().nth(1).and_then(|x| x.parse().ok()).unwrap_or(0);
                    max = max.max(kb);
                }
            }
        }
    }
    max
}

fn self_hwm_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).and_then(|l| l.split_whitespace().nth(1).and_then(|x| x.parse().ok())))
        .unwrap_or(0)
}

pub struct EnvResult {
    pub action: String,
    pub compile: Duration,
    pub solve: Duration,
    pub cex: Option<Env>,
    /// The solver gave up (time limit) or failed.
    pub error: Option<String>,
}

/// `child ⇒ parent` for every action both are compiled for.
pub async fn implies(solver: &mut Solver, schema: &Schema, envs: &HashMap<String, RequestEnv>, child: &Compiled, parent: &Compiled) -> Result<Vec<EnvResult>> {
    let mut out = vec![];
    for (action, cp) in &child.sets {
        let pp = &parent.sets.iter().find(|(a, _)| a == action).unwrap().1;
        let env = &envs[action];
        let t0 = Instant::now();
        let c = CompiledPolicySet::compile(&pset(cp)?, env, schema)?;
        let p = CompiledPolicySet::compile(&pset(pp)?, env, schema)?;
        let t1 = Instant::now();
        let (cex, error) = match solver.check_implies_with_counterexample_opt(&c, &p).await {
            Ok(c) => (c, None),
            Err(e) => {
                *solver = new_solver()?;
                (None, Some(e.to_string()))
            }
        };
        let t2 = Instant::now();
        out.push(EnvResult { action: action.clone(), compile: t1 - t0, solve: t2 - t1, cex, error });
    }
    Ok(out)
}

pub fn str_attr(env: &Env, attr: &str) -> String {
    let r = env.request.resource().unwrap();
    match env.entities.get(r).and_then(|e| e.attr(attr)) {
        Some(Ok(EvalResult::String(s))) => s,
        other => format!("{other:?}"),
    }
}

/// The request path of a counterexample, in either path model.
pub fn cex_path(env: &Env) -> String {
    if !seg::on() {
        return str_attr(env, "path");
    }
    let r = env.request.resource().unwrap();
    let e = env.entities.get(r).unwrap();
    let depth = match e.attr("depth") {
        Some(Ok(EvalResult::Long(d))) => d,
        _ => 0,
    };
    let segs: Vec<String> = (0..depth.clamp(0, seg::MAX_DEPTH as i64)).map(|i| str_attr(env, &format!("s{i}"))).collect();
    format!("/{}", segs.join("/"))
}

pub fn ctx_val(env: &Env, k: &str) -> Option<EvalResult> {
    env.request.context().and_then(|c| c.get(k))
}

fn ctx_long(env: &Env, k: &str) -> i64 {
    match ctx_val(env, k) {
        Some(EvalResult::Long(i)) => i,
        _ => i64::MIN,
    }
}

fn ctx_str(env: &Env, k: &str) -> String {
    match ctx_val(env, k) {
        Some(EvalResult::String(s)) => s,
        o => format!("{o:?}"),
    }
}

fn res_id(env: &Env) -> String {
    env.request.resource().map(|r| r.id().unescaped().to_string()).unwrap_or_default()
}

/// A counterexample as a sentence, plus whether a concrete replay confirms it.
fn explain(action: &str, env: &Env, c: &ZoneSpec, p: &ZoneSpec, forbid_check: bool) -> (String, Option<bool>) {
    if HTTP.contains(&action) {
        let host = str_attr(env, "host");
        let path = cex_path(env);
        let dangerous = matches!(ctx_val(env, "dangerous"), Some(EvalResult::Bool(true)));
        let cv = oracle::eval(c, action, &host, &path, dangerous);
        let pv = oracle::eval(p, action, &host, &path, dangerous);
        let d = if dangerous { " (rated dangerous, R3+)" } else { "" };
        if forbid_check {
            let confirmed = !matches!(cv, oracle::V::Forbidden(_) | oracle::V::Invalid) && matches!(pv, oracle::V::Forbidden(_));
            return (format!("{action} https://{host}{path}{d} is not forbidden in the child ({}), but the parent {}", oracle::describe(c, &cv), oracle::describe(p, &pv)), Some(confirmed));
        }
        let confirmed = matches!(cv, oracle::V::Allow(_)) && !matches!(pv, oracle::V::Allow(_));
        return (format!("{action} https://{host}{path}{d}: the child {}; the parent {}", oracle::describe(c, &cv), oracle::describe(p, &pv)), Some(confirmed));
    }
    let s = match action {
        "run_with" => {
            let f = |k: &str| ctx_long(env, k);
            format!(
                "run with memory {} MiB, {} millicpus, {} pids, timeout {} s, isolation level {}, {} children: allowed by the child, not by the parent",
                f("memory_mb"),
                f("millicpus"),
                f("pids"),
                f("timeout_s"),
                f("isolation"),
                f("children")
            )
        }
        "start_image" => format!("start image {:?}: the child may, the parent may not", res_id(env)),
        "accept_message" => format!("accept messages from zone {:?}: the child does, the parent doesn't", res_id(env)),
        "inject" => format!("inject secret {:?} into {} {} as {:?}: the child does, the parent doesn't", res_id(env), ctx_str(env, "host"), ctx_str(env, "header"), ctx_str(env, "format")),
        "use_model" => format!(
            "model route {:?} with {} requests, {} output tokens, server tools {:?}: the child may, the parent may not",
            res_id(env),
            ctx_long(env, "requests"),
            ctx_long(env, "output_tokens"),
            ctx_val(env, "server_tools")
        ),
        "ask_unlisted" => "ask for hosts outside reach: the child may (escalate), the parent hides them".into(),
        _ => format!("{env}"),
    };
    (s, None)
}

fn child_extras(c: &cases::Child) -> Extras {
    let mut images = vec![c.image.clone()];
    images.extend(c.zone.images.iter().cloned());
    Extras {
        images,
        accept_from: c.zone.accept_from.clone(),
        children: c.max_children as i64,
        timeout_s: c.zone.limits.timeout().map(|d| d.as_secs() as i64).unwrap_or(i64::MAX),
        llm_budget: c.zone.llm.as_ref().map(|l| (l.max_requests, l.max_output_tokens)),
    }
}

fn parent_extras(p: &cases::Parent) -> Extras {
    let mut accept = p.zone.accept_from.clone();
    accept.push(p.zone.name.clone());
    Extras {
        images: p.images.clone(),
        accept_from: accept,
        children: p.child_slots as i64 - 1,
        timeout_s: p.time_remaining.as_secs() as i64,
        llm_budget: p.zone.llm.as_ref().map(|_| p.llm_remaining.unwrap_or((i64::MAX as u64, i64::MAX as u64))),
    }
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if v.is_empty() {
        return f64::NAN;
    }
    v[v.len() / 2]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Run the zone and forbid checks for one child against its parent.
struct CaseRun {
    total_ms: f64,
    compile_ms: f64,
    solve_ms: f64,
    max_env_ms: f64,
    cex: Vec<(String, String, Option<bool>)>,
    errors: Vec<String>,
    exact: bool,
}

async fn run_case(solver: &mut Solver, schema: &Schema, envs: &HashMap<String, RequestEnv>, c: &cases::Child, p: &cases::Parent) -> Result<CaseRun> {
    let t0 = Instant::now();
    let cz = compile::compile_zone(&c.zone, &child_extras(c), Mode::Over);
    let pz = compile::compile_zone(&p.zone, &parent_extras(p), Mode::Under);
    let cf = compile::compile_not_forbidden(&c.zone, Mode::Over);
    let pf = compile::compile_not_forbidden(&p.zone, Mode::Under);
    let gen = t0.elapsed();
    let mut r1 = implies(solver, schema, envs, &cz, &pz).await?;
    let r2 = implies(solver, schema, envs, &cf, &pf).await?;
    let total = t0.elapsed();
    let mut cex = vec![];
    let mut errors = vec![];
    let n1 = r1.len();
    r1.extend(r2);
    let mut compile_t = gen;
    let mut solve_t = Duration::ZERO;
    let mut max_env = 0f64;
    for (k, r) in r1.iter().enumerate() {
        compile_t += r.compile;
        solve_t += r.solve;
        max_env = max_env.max(ms(r.compile + r.solve));
        if let Some(e) = &r.error {
            errors.push(format!("{}{}: {e} after {:.0} ms", if k >= n1 { "not-forbidden/" } else { "" }, r.action, ms(r.solve)));
        }
        if let Some(e) = &r.cex {
            let fc = k >= n1;
            let (s, conf) = explain(&r.action, e, &c.zone, &p.zone, fc);
            cex.push((format!("{}{}", if fc { "not-forbidden/" } else { "" }, r.action), s, conf));
        }
    }
    Ok(CaseRun { total_ms: ms(total), compile_ms: ms(compile_t), solve_ms: ms(solve_t), max_env_ms: max_env, cex, errors, exact: cz.exact && pz.exact && cf.exact && pf.exact })
}

/// Per-rule explanations: which child reach rules are not within the parent.
async fn per_rule(solver: &mut Solver, schema: &Schema, envs: &HashMap<String, RequestEnv>, c: &ZoneSpec, p: &ZoneSpec) -> Result<(Vec<String>, f64)> {
    let t0 = Instant::now();
    let mut out = vec![];
    for (i, r) in c.reach.iter().enumerate() {
        for m in HTTP.iter().filter(|m| r.methods.iter().any(|x| x.eq_ignore_ascii_case(m))) {
            let mut ex = true;
            let cp = compile::http_policies(c, m, Mode::Over, &mut ex, Some(i));
            let pp = compile::http_policies(p, m, Mode::Under, &mut ex, None);
            let env = &envs[*m];
            let cc = CompiledPolicySet::compile(&pset(&cp)?, env, schema)?;
            let pc = CompiledPolicySet::compile(&pset(&pp)?, env, schema)?;
            let t = Instant::now();
            let res = match solver.check_implies_with_counterexample_opt(&cc, &pc).await {
                Ok(r) => r,
                Err(e) => {
                    *solver = new_solver()?;
                    out.push(format!("reach rule {i} ({} {:?}) {m}: solver gave up after {:.0} ms ({e})", r.host, r.paths, ms(t.elapsed())));
                    None
                }
            };
            if let Some(e) = res {
                let host = str_attr(&e, "host");
                let path = cex_path(&e);
                let pv = oracle::eval(p, m, &host, &path, matches!(ctx_val(&e, "dangerous"), Some(EvalResult::Bool(true))));
                let real = !matches!(pv, oracle::V::Allow(_));
                out.push(format!("reach rule {i} ({} {:?}): {m} https://{host}{path}{} — parent: {}{}", r.host, r.paths, if matches!(ctx_val(&e, "dangerous"), Some(EvalResult::Bool(true))) { " [dangerous]" } else { "" }, oracle::describe(p, &pv), if real { "" } else { "  [SPURIOUS: the parent does allow it]" }));
            }
        }
    }
    Ok((out, ms(t0.elapsed())))
}

fn subset_check(c: &cases::Child, p: &cases::Parent) -> (Result<(), Vec<String>>, f64) {
    let b = subset::Bounds { zone: &p.zone, images: p.images.clone(), llm_remaining: p.llm_remaining, time_remaining: p.time_remaining, child_slots: p.child_slots };
    let a = subset::Ask { zone: &c.zone, image: &c.image, max_children: c.max_children };
    let n = 200;
    let t0 = Instant::now();
    for _ in 0..n {
        std::hint::black_box(subset::check(&a, &b).ok());
    }
    let us = t0.elapsed().as_secs_f64() * 1e6 / n as f64;
    (subset::check(&a, &b), us)
}

async fn zones(runs: usize) -> Result<()> {
    let (schema, _) = Schema::from_cedarschema_str(&compile::schema_text())?;
    let envs = envs(&schema);
    let parents = cases::parents();
    let children = cases::children();
    let mut solver = new_solver()?;
    let mut hwm = 0;
    println!("## Zone containment: child ⇒ parent (reach+limits+images+accept+inject+model+unlisted: 13 actions) and not-forbidden(child) ⇒ not-forbidden(parent) (7 actions)\n");
    println!("| case | parent | expected | SymCC | replay | subset.rs | exact encoding | median total ms | compile ms | solve ms | slowest action ms | cold ms | subset.rs µs |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|");
    let mut details = vec![];
    let filter = std::env::var("CASES").ok();
    for c in &children {
        if filter.as_ref().is_some_and(|f| !f.split(',').any(|f| c.name.starts_with(f))) {
            continue;
        }
        let p = parents.iter().find(|p| p.key == c.parent).unwrap();
        let mut totals = vec![];
        let mut comp = vec![];
        let mut solve = vec![];
        let mut maxe = vec![];
        let mut last = None;
        for _ in 0..runs {
            let r = run_case(&mut solver, &schema, &envs, c, p).await?;
            totals.push(r.total_ms);
            comp.push(r.compile_ms);
            solve.push(r.solve_ms);
            maxe.push(r.max_env_ms);
            hwm = hwm.max(cvc5_hwm_kib());
            last = Some(r);
        }
        // Cold: a fresh cvc5 process for the whole check.
        let t0 = Instant::now();
        let mut cold_solver = new_solver()?;
        let _ = run_case(&mut cold_solver, &schema, &envs, c, p).await?;
        let cold = ms(t0.elapsed());
        hwm = hwm.max(cvc5_hwm_kib());
        drop(cold_solver);
        let r = last.unwrap();
        let symcc_within = r.cex.is_empty() && r.errors.is_empty();
        let all_confirmed = r.cex.iter().all(|(_, _, conf)| conf.unwrap_or(true));
        let any_confirmed = r.cex.iter().any(|(_, _, conf)| conf.unwrap_or(true));
        let replay = if r.cex.is_empty() { "-".to_string() } else if all_confirmed { "all confirmed".into() } else if any_confirmed { "some spurious".into() } else { "all spurious".into() };
        let (sub, sub_us) = subset_check(c, p);
        let sub_s = match &sub {
            Ok(()) => "within".to_string(),
            Err(v) => format!("{} violation(s)", v.len()),
        };
        let verdict = if symcc_within {
            "within".to_string()
        } else if r.errors.is_empty() {
            format!("{} cex", r.cex.len())
        } else {
            format!("{} cex, {} solver timeout(s)", r.cex.len(), r.errors.len())
        };
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {:.0} | {:.0} | {:.0} | {:.0} | {:.0} | {:.1} |",
            c.name,
            c.parent,
            if c.within { "within".to_string() } else { format!("wider: {}", c.note) },
            verdict,
            replay,
            sub_s,
            if r.exact { "yes" } else { "no" },
            median(totals),
            median(comp),
            median(solve),
            median(maxe),
            cold,
            sub_us
        );
        let mut d = format!("### {} (parent {}): {}\n\nexpected: {}\n\n", c.name, c.parent, c.note, if c.within { "within" } else { "wider" });
        for (a, s, conf) in &r.cex {
            d.push_str(&format!("- [{a}] {s}{}\n", match conf {
                Some(true) => "  (replay: confirmed)",
                Some(false) => "  (replay: SPURIOUS)",
                None => "",
            }));
        }
        for e in &r.errors {
            d.push_str(&format!("- solver gave up: {e}\n"));
        }
        if !r.cex.is_empty() || !r.errors.is_empty() {
            let (pr, pr_ms) = per_rule(&mut solver, &schema, &envs, &c.zone, &p.zone).await?;
            d.push_str(&format!("\nper-rule explanation ({pr_ms:.0} ms, {} finding(s)):\n", pr.len()));
            for s in pr {
                d.push_str(&format!("  - {s}\n"));
            }
        }
        if let Err(v) = &sub {
            d.push_str("\nsubset.rs says:\n");
            for s in v {
                d.push_str(&format!("  - {s}\n"));
            }
        }
        details.push(d);
    }
    println!("\npeak cvc5 RSS {} MiB; harness peak RSS {} MiB\n", hwm / 1024, self_hwm_kib() / 1024);
    println!("## Counterexamples and explanations\n");
    for d in details {
        println!("{d}");
    }
    // One raw SymCC counterexample, as SymCC prints it.
    let c = children.iter().find(|c| c.name == "sh-wider-path").unwrap();
    let p = parents.iter().find(|p| p.key == c.parent).unwrap();
    let cz = compile::compile_zone(&c.zone, &child_extras(c), Mode::Over);
    let pz = compile::compile_zone(&p.zone, &parent_extras(p), Mode::Under);
    for r in implies(&mut solver, &schema, &envs, &cz, &pz).await? {
        if let Some(e) = r.cex {
            println!("raw SymCC counterexample for sh-wider-path, action {}:\n```\n{e}\n```\n", r.action);
        }
    }
    Ok(())
}

async fn scale(runs: usize) -> Result<()> {
    let (schema, _) = Schema::from_cedarschema_str(&compile::schema_text())?;
    let envs = envs(&schema);
    let mut solver = new_solver()?;
    let x = Extras { images: vec!["i".into()], accept_from: vec![], children: 0, timeout_s: 1800, llm_budget: Some((300, 400_000)) };
    println!("## Scaling: synthetic parent with N reach rules (1/3 one-segment *, 1/10 wildcard hosts), child narrows every rule\n");
    println!("| N rules | child | SymCC (whole zone per action) | median total ms | median solve ms | slowest action ms | policy text KiB | peak cvc5 MiB | per child rule, parent sliced by host (1 run) |");
    println!("|---|---|---|---|---|---|---|---|---|");
    for n in [10usize, 30, 100, 300] {
        for widen in [false, true] {
            let (p, c) = cases::synthetic(n, widen);
            let mut t = vec![];
            let mut s = vec![];
            let mut mx = vec![];
            let mut verdict = String::new();
            let mut text = 0;
            for _ in 0..runs {
                let t0 = Instant::now();
                let cz = compile::compile_zone(&c, &x, Mode::Over);
                let pz = compile::compile_zone(&p, &x, Mode::Under);
                text = pz.sets.iter().flat_map(|(_, v)| v.iter().map(|p| p.text.len())).sum::<usize>() + cz.sets.iter().flat_map(|(_, v)| v.iter().map(|p| p.text.len())).sum::<usize>();
                let r = implies(&mut solver, &schema, &envs, &cz, &pz).await?;
                t.push(ms(t0.elapsed()));
                s.push(r.iter().map(|r| ms(r.solve)).sum());
                mx.push(r.iter().map(|r| ms(r.solve + r.compile)).fold(0f64, f64::max));
                let ce: Vec<String> = r.iter().filter_map(|r| r.cex.as_ref().map(|e| format!("{} {}{}", r.action, str_attr(e, "host"), cex_path(e)))).collect();
                let errs: Vec<String> = r.iter().filter(|r| r.error.is_some()).map(|r| format!("{} gave up after {:.0} s", r.action, r.solve.as_secs_f64())).collect();
                verdict = if ce.is_empty() && errs.is_empty() { "within".into() } else { format!("{}{}", if ce.is_empty() { String::new() } else { format!("cex: {}", ce.join("; ")) }, if errs.is_empty() { String::new() } else { format!(" UNKNOWN: {}", errs.join("; ")) }) };
            }
            let (sl_ms, sl_q, sl_max, sl_found) = sliced(&mut solver, &schema, &envs, &c, &p).await?;
            println!(
                "| {n} | {} | {verdict} | {:.0} | {:.0} | {:.0} | {} | {} | {sl_ms:.0} ms, {sl_q} queries, slowest {sl_max:.0} ms: {sl_found} |",
                if widen { "one rule widened" } else { "within" },
                median(t),
                median(s),
                median(mx),
                text / 1024,
                cvc5_hwm_kib() / 1024
            );
        }
    }
    Ok(())
}

fn host_overlap(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    match (a.strip_prefix("*."), b.strip_prefix("*.")) {
        (None, None) => a == b,
        (Some(s), None) => b.ends_with(&format!(".{s}")),
        (None, Some(t)) => a.ends_with(&format!(".{t}")),
        (Some(s), Some(t)) => s == t || s.ends_with(&format!(".{t}")) || t.ends_with(&format!(".{s}")),
    }
}

/// Per child reach rule and method, against only the parent rules whose host can overlap (a
/// sound slice: other parent rules can't match any request the child rule allows).
async fn sliced(solver: &mut Solver, schema: &Schema, envs: &HashMap<String, RequestEnv>, c: &ZoneSpec, p: &ZoneSpec) -> Result<(f64, usize, f64, String)> {
    let t0 = Instant::now();
    let (mut q, mut max, mut found) = (0, 0f64, vec![]);
    for (i, r) in c.reach.iter().enumerate() {
        let mut ps = p.clone();
        ps.reach.retain(|x| host_overlap(&x.host, &r.host));
        ps.forbid.retain(|x| host_overlap(&x.host, &r.host));
        for m in HTTP.iter().filter(|m| r.methods.iter().any(|x| x.eq_ignore_ascii_case(m))) {
            let mut ex = true;
            let cp = compile::http_policies(c, m, Mode::Over, &mut ex, Some(i));
            let pp = compile::http_policies(&ps, m, Mode::Under, &mut ex, None);
            let env = &envs[*m];
            let t = Instant::now();
            let cc = CompiledPolicySet::compile(&pset(&cp)?, env, schema)?;
            let pc = CompiledPolicySet::compile(&pset(&pp)?, env, schema)?;
            match solver.check_implies_with_counterexample_opt(&cc, &pc).await {
                Ok(Some(e)) => found.push(format!("rule {i}: {m} {}{}", str_attr(&e, "host"), cex_path(&e))),
                Ok(None) => {}
                Err(_) => {
                    *solver = new_solver()?;
                    found.push(format!("rule {i}: {m} UNKNOWN"));
                }
            }
            q += 1;
            max = max.max(ms(t.elapsed()));
        }
    }
    Ok((ms(t0.elapsed()), q, max, if found.is_empty() { "within".into() } else { found.join("; ") }))
}

/// Difference test the compiler: concrete Cedar evaluation of the Over and Under encodings against
/// the oracle (wicket's own glob and host matching) on generated requests.
fn difftest() -> Result<()> {
    let (schema, _) = Schema::from_cedarschema_str(&compile::schema_text())?;
    let mut zones: Vec<ZoneSpec> = cases::parents().into_iter().map(|p| p.zone).collect();
    zones.extend(cases::children().into_iter().map(|c| c.zone));
    zones.push(cases::synthetic(30, false).0);
    zones.push(cases::synthetic(30, true).1);
    let auth = Authorizer::new();
    let (mut n, mut bad_over, mut bad_under, mut inexact_diff, mut exact_bad) = (0, 0, 0, 0, 0);
    let mut examples = vec![];
    for z in &zones {
        let mut hosts: HashSet<String> = ["example.org".into(), "evil.com".into()].into();
        let mut paths: HashSet<String> = ["/".into(), "/x".into(), "/a/b/c".into()].into();
        for (h, ps) in z.reach.iter().map(|r| (&r.host, &r.paths)).chain(z.forbid.iter().map(|f| (&f.host, &f.paths))) {
            match h.strip_prefix("*.") {
                Some(s) => {
                    hosts.insert(format!("a.{s}"));
                    hosts.insert(format!("b.a.{s}"));
                    hosts.insert(s.to_string());
                }
                None => {
                    hosts.insert(h.clone());
                }
            }
            for g in ps {
                for e in glob::expand_braces(g) {
                    for fill in ["", "x", "x/y", "abc/worker/q"] {
                        for sfill in ["", "s1", "a/b"] {
                            let p = e.replace("**", "\u{1}").replace('*', sfill).replace('\u{1}', fill).replace("//", "/");
                            paths.insert(p.clone());
                            paths.insert(format!("{p}/"));
                            paths.insert(format!("{p}/more"));
                            if let Some((pre, _)) = p.rsplit_once('/') {
                                paths.insert(if pre.is_empty() { "/".into() } else { pre.to_string() });
                            }
                        }
                    }
                }
            }
        }
        for mode in [Mode::Over, Mode::Under] {
            let mut ex = true;
            let sets: Vec<(String, PolicySet)> = HTTP.iter().map(|m| (m.to_string(), pset(&compile::http_policies(z, m, mode, &mut ex, None)).unwrap())).collect();
            for (m, ps) in &sets {
                for h in &hosts {
                    for p in &paths {
                        for d in [false, true] {
                            let o = oracle::eval(z, m, h, p, d);
                            if o == oracle::V::Invalid || (seg::on() && seg::split(p).len() > seg::MAX_DEPTH) {
                                continue;
                            }
                            n += 1;
                            let want = matches!(o, oracle::V::Allow(_));
                            let got = cedar_allows(&auth, &schema, m, h, p, d, ps)?;
                            if got != want {
                                if ex {
                                    exact_bad += 1;
                                } else {
                                    inexact_diff += 1;
                                }
                                match (mode, got) {
                                    (Mode::Over, false) => bad_over += 1,
                                    (Mode::Under, true) => bad_under += 1,
                                    _ => {}
                                }
                                if examples.len() < 40 && (ex || (mode == Mode::Over && !got) || (mode == Mode::Under && got)) {
                                    examples.push(format!("{} {mode:?} {m} {h}{p} dangerous={d}: oracle {want} cedar {got}", z.name));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    println!("## Compiler difference test\n");
    println!("{n} (zone, mode, request) evaluations; Over not a superset: {bad_over}; Under not a subset: {bad_under}; mismatches where the encoding claims exact: {exact_bad}; (allowed) differences where it is approximate: {inexact_diff}");
    for e in examples {
        println!("- {e}");
    }
    Ok(())
}

fn cedar_allows(auth: &Authorizer, schema: &Schema, m: &str, h: &str, p: &str, d: bool, ps: &PolicySet) -> Result<bool> {
    let uid = EntityUid::from_type_name_and_id("Url".parse()?, EntityId::new("u"));
    let mut attrs = HashMap::from([("host".to_string(), RestrictedExpression::new_string(h.into()))]);
    if seg::on() {
        let segs = seg::split(p);
        if segs.len() > seg::MAX_DEPTH {
            return Ok(false);
        }
        attrs.insert("depth".into(), RestrictedExpression::new_long(segs.len() as i64));
        for i in 0..seg::MAX_DEPTH {
            attrs.insert(format!("s{i}"), RestrictedExpression::new_string(segs.get(i).cloned().unwrap_or_default()));
        }
    } else {
        attrs.insert("path".into(), RestrictedExpression::new_string(p.into()));
    }
    let ent = Entities::from_entities([Entity::new(uid.clone(), attrs, HashSet::new())?], Some(schema))?;
    let ctx = Context::from_pairs([("dangerous".to_string(), RestrictedExpression::new_bool(d))])?;
    let princ = EntityUid::from_type_name_and_id("Agent".parse()?, EntityId::new("a"));
    let act = EntityUid::from_type_name_and_id("Action".parse()?, EntityId::new(m));
    let req = Request::new(princ, act, uid, ctx, Some(schema))?;
    Ok(auth.is_authorized(&req, ps, &ent).decision() == Decision::Allow)
}

/// globset semantics the encoding depends on.
fn probe() {
    for (g, p) in [
        ("/x/**", "/x"),
        ("/x/**", "/x/"),
        ("/x/**", "/x/a/b"),
        ("/**", "/"),
        ("/a/**/b", "/a/b"),
        ("/a/**/b", "/a/x/y/b"),
        ("/a/*", "/a/"),
        ("/a/*", "/a/b/c"),
        ("/a**b", "/a/x/b"),
        ("/a/{b,c}/*", "/a/c/d"),
        ("/v1/code/sessions/*/worker/**", "/v1/code/sessions/abc/worker/x/worker/y"),
    ] {
        println!("probe: {g:?} matches {p:?}: {}", oracle::glob_match(g, p));
    }
}

/// A's CI band: org floor ⊆ manifest ⊆ ceiling, with the same compiler.
async fn band(runs: usize) -> Result<()> {
    let (schema, _) = Schema::from_cedarschema_str(&compile::schema_text())?;
    let envs = envs(&schema);
    let mut solver = new_solver()?;
    let floor = cases::zone("floor", "  reach:\n    - { host: index.crates.io }\n    - { host: static.crates.io }\n    - { host: github.com, methods: [GET, POST], paths: [\"/public/wicket.git/info/refs\", \"/public/wicket.git/git-upload-pack\"] }\n  limits: { memory: 1g, cpus: 1, timeout: 30m, pids: 512 }\n");
    let ceiling = cases::zone("ceiling", "  reach:\n    - { host: index.crates.io }\n    - { host: static.crates.io }\n    - { host: \"*.crates.io\" }\n    - { host: github.com, methods: [GET, POST], paths: [\"/public/*/info/refs\", \"/public/*/git-upload-pack\"] }\n    - { host: api.github.com, methods: [GET, HEAD], paths: [\"/repos/public/**\"] }\n  forbid:\n    - { host: mcp-proxy.anthropic.com }\n  limits: { memory: 4g, cpus: 4, timeout: 4h, pids: 8192 }\n");
    let manifest = cases::parents().into_iter().find(|p| p.key == "self-hosting").unwrap().zone;
    let mut push = manifest.clone();
    push.reach.push(serde_yaml::from_str("{ host: github.com, methods: [POST], paths: [\"/public/wicket.git/git-receive-pack\"] }")?);
    let mut no_crates = manifest.clone();
    no_crates.reach.retain(|r| r.host != "static.crates.io");
    let x = |z: &ZoneSpec| Extras {
        images: vec![],
        accept_from: vec![],
        children: 0,
        timeout_s: z.limits.timeout().map(|d| d.as_secs() as i64).unwrap_or(0),
        llm_budget: None,
    };
    // Only reach (HTTP) and limits matter for the band.
    let only = |c: compile::Compiled| Compiled { sets: c.sets.into_iter().filter(|(a, _)| HTTP.contains(&a.as_str()) || a == "run_with").collect(), exact: c.exact };
    println!("## A: org floor ⊆ manifest ⊆ ceiling (reach + limits; 8 actions per check)\n");
    println!("| check | expected | SymCC | median ms | counterexample |");
    println!("|---|---|---|---|---|");
    for (name, lo, hi, want) in [
        ("floor ⊆ self-hosting manifest", &floor, &manifest, true),
        ("self-hosting manifest ⊆ ceiling", &manifest, &ceiling, true),
        ("manifest + push ⊆ ceiling", &push, &ceiling, false),
        ("floor ⊆ manifest without static.crates.io", &floor, &no_crates, false),
    ] {
        let mut t = vec![];
        let mut ce = String::new();
        for _ in 0..runs {
            let t0 = Instant::now();
            let r = implies(&mut solver, &schema, &envs, &only(compile::compile_zone(lo, &x(lo), Mode::Over)), &only(compile::compile_zone(hi, &x(hi), Mode::Under))).await?;
            t.push(ms(t0.elapsed()));
            ce = r
                .iter()
                .filter_map(|r| r.cex.as_ref().map(|e| explain(&r.action, e, lo, hi, false).0))
                .collect::<Vec<_>>()
                .join("<br>");
        }
        println!("| {name} | {} | {} | {:.0} | {} |", if want { "holds" } else { "fails" }, if ce.is_empty() { "holds" } else { "fails" }, median(t), if ce.is_empty() { "-".into() } else { ce });
    }
    // Does the manifest keep the ceiling's forbids (what the ceiling refuses outright, the
    // manifest must not even let an agent ask for)?
    let mut t = vec![];
    let mut ce = String::new();
    for _ in 0..runs {
        let t0 = Instant::now();
        let r = implies(&mut solver, &schema, &envs, &compile::compile_not_forbidden(&manifest, Mode::Over), &compile::compile_not_forbidden(&ceiling, Mode::Under)).await?;
        t.push(ms(t0.elapsed()));
        ce = r.iter().filter_map(|r| r.cex.as_ref().map(|e| explain(&r.action, e, &manifest, &ceiling, true).0)).take(2).collect::<Vec<_>>().join("<br>");
    }
    println!("| self-hosting manifest keeps the ceiling's forbids (7 actions) | fails (it has no forbid list) | {} | {:.0} | {} |", if ce.is_empty() { "holds" } else { "fails" }, median(t), if ce.is_empty() { "-".into() } else { format!("{ce} (one per method)") });
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if std::env::var("SEG").is_ok_and(|v| v == "1") {
        seg::enable();
    }
    let runs: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    match args.get(1).map(String::as_str) {
        Some("probe") => probe(),
        Some("difftest") => difftest()?,
        Some("zones") => zones(runs).await?,
        Some("scale") => scale(runs).await?,
        Some("band") => band(runs).await?,
        Some("org") => org::run(runs).await?,
        Some("policies") => {
            // Print the compiled policies for one child and its parent, for the write-up.
            let name = args.get(2).cloned().unwrap_or("sh-issues-reader".into());
            let c = cases::children().into_iter().find(|c| c.name == name).unwrap();
            let p = cases::parents().into_iter().find(|p| p.key == c.parent).unwrap();
            for (who, comp) in [("child", compile::compile_zone(&c.zone, &child_extras(&c), Mode::Over)), ("parent", compile::compile_zone(&p.zone, &parent_extras(&p), Mode::Under))] {
                for (a, pols) in comp.sets {
                    if a == "GET" || a == "run_with" {
                        println!("// {who} {a}");
                        for p in pols {
                            println!("@id({:?})\n{}\n", p.id, p.text);
                        }
                    }
                }
            }
        }
        _ => eprintln!("usage: symcc-zones probe|difftest|zones [runs]|scale [runs]|band [runs]|org [runs]|policies [child]"),
    }
    Ok(())
}
