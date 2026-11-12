//! Does an org policy change narrow or widen what boxes may do? (#51, design §4.1)
//!
//! For every request environment of wicket's schema (one per action), SymCC (with cvc5) is asked
//! whether everything the new policy set allows the old one allows too (`new ⇒ old`). If so for
//! every action, the change narrows (or keeps) authority and needs no decision; otherwise it widens,
//! and each counterexample (a request the new set allows and the old doesn't) is shown.
//!
//! - cvc5 runs with a per-query time limit; a timeout, an `unknown` or a solver error is a failure,
//!   never a pass.
//! - Path globs are opaque to the solver: `path_matches.contains("<glob>")` is a set membership it
//!   knows nothing more about, so a changed glob reads as "may widen" even where it narrows (a
//!   human then decides). Hosts, methods, risk, images, zones and groups are exact.
//! - Policies are analysed for every principal, not one box: wider than at mint, so sound.

use anyhow::{anyhow, bail, Result};
use cedar_policy::{PolicySet, Schema};
use cedar_policy_symcc::solver::LocalSolver;
use cedar_policy_symcc::{CedarSymCompiler, CompiledPolicySet};

/// One action's answer.
#[derive(Debug)]
pub struct ActionDiff {
    pub action: String,
    /// A request the new policy allows and the old doesn't (None: it narrows for this action).
    pub widens: Option<String>,
}

/// The per-query time limit for cvc5, ms (`WICKET_SYMCC_TLIMIT_MS`, default 10 s).
fn tlimit_ms() -> u64 {
    std::env::var("WICKET_SYMCC_TLIMIT_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(10_000)
}

fn solver() -> Result<CedarSymCompiler<LocalSolver>> {
    // `--tlimit` would bound cvc5's whole life (experiment #58); `--tlimit-per` bounds each query.
    let s = LocalSolver::cvc5_with_args([format!("--tlimit-per={}", tlimit_ms())])
        .map_err(|e| anyhow!("starting cvc5 ($CVC5 or cvc5 on PATH): {e}"))?;
    CedarSymCompiler::new(s).map_err(|e| anyhow!("{e}"))
}

/// `new ⇒ old` for every action of wicket's schema.
pub async fn diff(old: &str, new: &str) -> Result<Vec<ActionDiff>> {
    let (old, new) = (wicket_policy::compile::parse(old)?, wicket_policy::compile::parse(new)?);
    diff_sets(&old, &new).await
}

pub async fn diff_sets(old: &PolicySet, new: &PolicySet) -> Result<Vec<ActionDiff>> {
    let schema: Schema = wicket_policy::schema::schema();
    let mut s = solver()?;
    let mut out = vec![];
    for env in schema.request_envs() {
        let action = env.action().id().unescaped().to_string();
        let o = CompiledPolicySet::compile(old, &env, &schema).map_err(|e| anyhow!("{action}: {e}"))?;
        let n = CompiledPolicySet::compile(new, &env, &schema).map_err(|e| anyhow!("{action}: {e}"))?;
        let cex = s
            .check_implies_with_counterexample_opt(&n, &o)
            .await
            .map_err(|e| anyhow!("{action}: the solver gave no answer (a timeout or `unknown` is a failure): {e}"))?;
        out.push(ActionDiff { action, widens: cex.map(|c| format!("{:?} with {:?}", c.request, c.entities)) });
    }
    if out.is_empty() {
        bail!("the schema has no request environments: nothing was compared");
    }
    Ok(out)
}
